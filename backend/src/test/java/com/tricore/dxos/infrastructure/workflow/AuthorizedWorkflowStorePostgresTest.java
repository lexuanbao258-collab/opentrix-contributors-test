// SPDX-FileCopyrightText: 2026 TRICORE contributors
//
// SPDX-License-Identifier: Apache-2.0

package com.tricore.dxos.infrastructure.workflow;

import com.tricore.dxos.application.authorization.WorkflowAccessException;
import com.tricore.dxos.application.authorization.WorkflowAclSnapshotReader.ResourceAclSnapshot;
import com.tricore.dxos.application.authorization.WorkflowOperation;
import com.tricore.dxos.application.workflow.AuthorizedWorkflowService;
import com.tricore.dxos.application.workflow.TenantSelectionRequiredException;
import com.tricore.dxos.core.identity.AuthenticatedPrincipal;
import com.tricore.dxos.core.identity.Authority;
import com.tricore.dxos.core.workflow.ResourceReference;
import com.tricore.dxos.core.workflow.TransitionCommand;
import com.tricore.dxos.core.workflow.TransitionResult;
import com.tricore.dxos.core.workflow.WorkflowErrorCode;
import com.tricore.dxos.core.workflow.WorkflowException;
import com.tricore.dxos.core.workflow.WorkflowInstance;
import com.tricore.dxos.core.workflow.WorkflowRuntime;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Real NOSUPERUSER runtime role holding only db/workflow-policy/runtime-grants.sql, against a schema
 * migrated by real Flyway (V1-V4 plus the V5 policy candidate) as a NOSUPERUSER schema owner.
 * Proves the adapter on the candidate migration; the reviewed production pipeline does not include V5 yet.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@EnabledIfEnvironmentVariable(named = "HELPDESK_DISPOSABLE_URL",
        matches = "jdbc:postgresql://127\\.0\\.0\\.1:55439/helpdesk_disposable_test")
class AuthorizedWorkflowStorePostgresTest {
    private static final Set<String> ALL = Set.of("workflow:create", "workflow:activate", "workflow:transition", "workflow:read");
    private static final String ALICE = "oidc:alice";     // tenant-a
    private static final String BOB = "oidc:bob";         // tenant-b
    private static final String CAROL = "oidc:carol";     // tenant-a and tenant-b
    private static final String DAVE = "oidc:dave";       // tenant-a, no grants
    private static final String OUTSIDER = "oidc:outsider"; // no membership

    private WorkflowPolicyFixture db;
    private String url, schema, runtimeRole;
    private DataSource runtime;
    private PostgresAuthorizedWorkflowStore store;

    @BeforeAll
    void setup() throws Exception {
        assertThat(System.getenv("WORKFLOW_EVENT_GUARD_LOCAL_DISPOSABLE")).isEqualTo("true");
        db = new WorkflowPolicyFixture();
        url = db.url;
        schema = db.schema;
        runtimeRole = db.runtimeRole;
        try (var c = admin()) {
            assertThat(number(c, "SHOW server_version_num")).isBetween(170000L, 179999L);
        }
        db.flyway(WorkflowPolicyFixture.MIGRATIONS, WorkflowPolicyFixture.POLICY_CANDIDATE).migrate();
        try (var c = db.migrator()) {
            c.setAutoCommit(false);
            sql(c, "INSERT INTO workflow_definitions(definition_id,definition_version,initial_state) VALUES('leave-request',1,'draft')");
            sql(c, "INSERT INTO workflow_definition_states VALUES('leave-request',1,'draft'),('leave-request',1,'submitted'),('leave-request',1,'approved')");
            sql(c, "INSERT INTO workflow_definition_transitions VALUES('leave-request',1,'submit','draft','submitted'),('leave-request',1,'approve','submitted','approved')");
            sql(c, "INSERT INTO tenant_guards VALUES('tenant-a',0),('tenant-b',0)");
            sql(c, "INSERT INTO tenant_memberships VALUES('tenant-a','" + ALICE + "',true),('tenant-b','" + BOB
                    + "',true),('tenant-a','" + CAROL + "',true),('tenant-b','" + CAROL + "',true),('tenant-a','" + DAVE + "',true)");
            c.commit();
        }
        db.grantRuntime();
        runtime = db.runtimeDataSource();
        store = new PostgresAuthorizedWorkflowStore(runtime, schema);
    }

    @AfterAll
    void cleanup() throws Exception {
        if (db != null) db.close();
    }

    // 1. Tenant A member with grants reaches tenant A resource; the write is durable and attributed.
    @Test
    void tenantMemberWithGrantsTransitionsOwnResource() throws Exception {
        String instance = instance("tenant-a", "leave_request", ALICE, acl(ALICE, "read", "transition"));

        TransitionResult result = service(ALICE).transition("tenant-a", instance, "submit", 0);

        assertThat(result.instance().currentState()).isEqualTo("submitted");
        assertThat(service(ALICE).get(null, instance).runtimeVersion()).isEqualTo(1);
        assertThat(text("SELECT actor_id FROM %s.workflow_transition_history WHERE instance_id='" + instance + "'"))
                .isEqualTo(ALICE);
    }

    // 2. Tenant A member cannot read tenant B resource, whatever tenant it claims.
    @Test
    void tenantAMemberCannotReadTenantBResource() throws Exception {
        String instance = instance("tenant-b", "leave_request", BOB, acl(BOB, "read", "transition"));

        assertDenied(() -> service(ALICE).get("tenant-a", instance), "HIDDEN");
        assertDenied(() -> service(ALICE).get(null, instance), "HIDDEN");
        assertDenied(() -> service(ALICE).get("tenant-b", instance), "HIDDEN");
        assertDenied(() -> service(ALICE).history("tenant-a", instance), "HIDDEN");
        assertDenied(() -> service(ALICE).get("tenant-a", "wf-missing-" + UUID.randomUUID()), "HIDDEN");
    }

    // 3 + 8. Tenant A member cannot transition tenant B resource; nothing changes.
    @Test
    void tenantAMemberCannotTransitionTenantBResource() throws Exception {
        String instance = instance("tenant-b", "leave_request", BOB, acl(BOB, "read", "transition"));

        assertDenied(() -> service(ALICE).transition("tenant-a", instance, "submit", 0), "HIDDEN");
        assertDenied(() -> service(ALICE).transition("tenant-b", instance, "submit", 0), "HIDDEN");
        assertUnchanged(instance);
    }

    // 4. Principal without any membership.
    @Test
    void principalWithoutMembershipIsHidden() throws Exception {
        String instance = instance("tenant-a", "leave_request", ALICE, acl(ALICE, "read"));

        assertDenied(() -> service(OUTSIDER).get(null, instance), "HIDDEN");
        assertDenied(() -> service(OUTSIDER).get("tenant-a", instance), "HIDDEN");
    }

    // 5. Multiple memberships require a valid explicit selection.
    @Test
    void multipleMembershipsRequireAValidSelection() throws Exception {
        String instance = instance("tenant-b", "leave_request", BOB, acl(BOB, "read"), acl(CAROL, "read"));

        assertThatThrownBy(() -> service(CAROL).get(null, instance))
                .isInstanceOf(TenantSelectionRequiredException.class);
        assertThat(service(CAROL).get("tenant-b", instance).instanceId()).isEqualTo(instance);
        assertDenied(() -> service(CAROL).get("tenant-a", instance), "HIDDEN");
    }

    @Test
    void multipleMembershipsWithoutSelectionFailOnWritesWithoutMutation() throws Exception {
        String instance = instance("tenant-b", "leave_request", BOB, acl(CAROL, "read", "transition"));

        assertThatThrownBy(() -> service(CAROL).transition(null, instance, "submit", 0))
                .isInstanceOf(TenantSelectionRequiredException.class);
        assertUnchanged(instance);
    }

    // 6. Missing ACL.
    @Test
    void memberWithoutAnyGrantIsHidden() throws Exception {
        String instance = instance("tenant-a", "leave_request", ALICE, acl(ALICE, "read", "transition"));

        assertDenied(() -> service(DAVE).get("tenant-a", instance), "HIDDEN");
        assertDenied(() -> service(DAVE).transition("tenant-a", instance, "submit", 0), "HIDDEN");
        assertUnchanged(instance);
    }

    @Test
    void readOnlyGrantCannotTransition() throws Exception {
        String instance = instance("tenant-a", "leave_request", ALICE, acl(ALICE, "read"));

        assertDenied(() -> service(ALICE).transition("tenant-a", instance, "submit", 0), "FORBIDDEN");
        assertUnchanged(instance);
    }

    @Test
    void revokedGrantIsNotUsed() throws Exception {
        String instance = instance("tenant-a", "leave_request", ALICE, acl(ALICE, "read", "transition"));
        admin("UPDATE %s.resource_acl SET granted=false WHERE actor_id='" + ALICE + "' AND operation='workflow:transition' AND resource_id='" + resourceOf(instance) + "'");

        assertDenied(() -> service(ALICE).transition("tenant-a", instance, "submit", 0), "FORBIDDEN");
        assertUnchanged(instance);
    }

    @Test
    void inactiveMembershipIsHidden() throws Exception {
        String member = "oidc:inactive-" + UUID.randomUUID();
        admin("INSERT INTO %s.tenant_memberships VALUES('tenant-a','" + member + "',true)");
        String instance = instance("tenant-a", "leave_request", ALICE, acl(member, "read"));
        admin("UPDATE %s.tenant_memberships SET active=false WHERE actor_id='" + member + "'");

        assertDenied(() -> service(member).get("tenant-a", instance), "HIDDEN");
    }

    // 7. Database/policy failures never become ALLOWED.
    @Test
    void policyTablePrivilegeLossIsUnavailable() throws Exception {
        String instance = instance("tenant-a", "leave_request", ALICE, acl(ALICE, "read", "transition"));
        admin("REVOKE SELECT ON %s.resource_acl FROM " + runtimeRole);
        try {
            assertDenied(() -> service(ALICE).transition("tenant-a", instance, "submit", 0), "UNAVAILABLE");
            assertDenied(() -> service(ALICE).get("tenant-a", instance), "UNAVAILABLE");
        } finally {
            admin("GRANT SELECT ON %s.resource_acl TO " + runtimeRole);
        }
        assertUnchanged(instance);
    }

    @Test
    void missingPolicySchemaIsUnavailable() throws Exception {
        String instance = instance("tenant-a", "leave_request", ALICE, acl(ALICE, "read"));
        var wrongSchema = new PostgresAuthorizedWorkflowStore(runtime, "authz_missing_" + UUID.randomUUID().toString().replace("-", ""));

        assertThatThrownBy(() -> new AuthorizedWorkflowService(() -> principal(ALICE), wrongSchema, Clock.systemUTC())
                .get("tenant-a", instance)).isInstanceOfSatisfying(WorkflowAccessException.class,
                failure -> assertThat(failure.decision().name()).isEqualTo("UNAVAILABLE"));
    }

    // 9. Rollback: a failure after the Workflow write inside the same transaction leaves nothing behind.
    @Test
    void failureAfterWriteRollsBackInstanceAndHistory() throws Exception {
        String instance = instance("tenant-a", "leave_request", ALICE, acl(ALICE, "read", "transition"));

        assertThatThrownBy(() -> store.inTransaction(true, session -> {
            assertThat(session.lockTenant("tenant-a", true)).isTrue();
            var workflow = session.workflow();
            WorkflowInstance current = workflow.loadInstance(instance);
            var definition = workflow.loadDefinition(current.definitionId(), current.definitionVersion());
            workflow.commitTransition(current.transition(definition, new TransitionCommand(instance, "submit",
                    new com.tricore.dxos.core.workflow.ActorReference(ALICE), 0), current.updatedAt()));
            assertThat(workflow.loadInstance(instance).runtimeVersion()).isEqualTo(1);
            throw new IllegalStateException("late failure");
        })).isInstanceOfSatisfying(WorkflowAccessException.class,
                failure -> assertThat(failure.decision().name()).isEqualTo("UNAVAILABLE"));
        assertUnchanged(instance);
    }

    @Test
    void staleExpectedVersionIsVersionConflictWithoutMutation() throws Exception {
        String instance = instance("tenant-a", "leave_request", ALICE, acl(ALICE, "read", "transition"));
        service(ALICE).transition("tenant-a", instance, "submit", 0);

        assertThatThrownBy(() -> service(ALICE).transition("tenant-a", instance, "approve", 0))
                .isInstanceOfSatisfying(WorkflowException.class,
                        failure -> assertThat(failure.code()).isEqualTo(WorkflowErrorCode.VERSION_CONFLICT));
        assertThat(number("SELECT count(*) FROM %s.workflow_transition_history WHERE instance_id='" + instance + "'")).isEqualTo(1);
    }

    @Test
    void sessionCannotBeUsedAfterItsTransaction() {
        var escaped = store.inTransaction(false, session -> session);

        assertThatThrownBy(() -> escaped.activeTenantIds(ALICE)).isInstanceOf(IllegalStateException.class);
    }

    // 10. Locking and concurrency.
    @Test
    void policyEditWaitsForAnAuthorizedWriteHoldingTheTenantLock() throws Exception {
        String instance = instance("tenant-a", "leave_request", ALICE, acl(ALICE, "read", "transition"));
        var locked = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        var writer = CompletableFuture.runAsync(() -> store.inTransaction(true, session -> {
            assertThat(session.lockTenant("tenant-a", true)).isTrue();
            locked.countDown();
            await(release);
            return null;
        }));
        try {
            assertThat(locked.await(10, TimeUnit.SECONDS)).isTrue();
            try (var c = admin()) {
                sql(c, "SET lock_timeout = '500ms'");
                assertThatThrownBy(() -> sql(c, ("UPDATE %s.resource_acl SET granted=false WHERE resource_id='"
                        + resourceOf(instance) + "'").formatted(schema)))
                        .isInstanceOfSatisfying(SQLException.class, failure -> assertThat(failure.getSQLState()).isEqualTo("55P03"));
            }
        } finally {
            release.countDown();
            writer.get(10, TimeUnit.SECONDS);
        }
    }

    @Test
    void writeWaitingOnTheTenantLockSeesARevocationCommittedMeanwhile() throws Exception {
        String instance = instance("tenant-a", "leave_request", ALICE, acl(ALICE, "read", "transition"));
        try (var policy = admin()) {
            policy.setAutoCommit(false);
            sql(policy, ("UPDATE %s.resource_acl SET granted=false WHERE actor_id='" + ALICE
                    + "' AND operation='workflow:transition' AND resource_id='" + resourceOf(instance) + "'").formatted(schema));
            var attempt = CompletableFuture.supplyAsync(() -> {
                try {
                    service(ALICE).transition("tenant-a", instance, "submit", 0);
                    return "ALLOWED";
                } catch (WorkflowAccessException denied) {
                    return denied.decision().name();
                }
            });
            waitForRuntimeLockWait();
            policy.commit();
            assertThat(attempt.get(10, TimeUnit.SECONDS)).isEqualTo("FORBIDDEN");
        }
        assertUnchanged(instance);
    }

    @Test
    void concurrentTransitionsWithTheSameExpectedVersionHaveOneWinner() throws Exception {
        String instance = instance("tenant-a", "leave_request", ALICE, acl(ALICE, "read", "transition"));
        var start = new CountDownLatch(1);
        List<CompletableFuture<String>> attempts = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            attempts.add(CompletableFuture.supplyAsync(() -> {
                await(start);
                try {
                    service(ALICE).transition("tenant-a", instance, "submit", 0);
                    return "OK";
                } catch (WorkflowException failure) {
                    return failure.code().name();
                }
            }));
        }
        start.countDown();
        List<String> outcomes = new ArrayList<>();
        for (var attempt : attempts) outcomes.add(attempt.get(30, TimeUnit.SECONDS));

        assertThat(outcomes).containsOnlyOnce("OK").containsOnly("OK", "VERSION_CONFLICT");
        assertThat(number("SELECT count(*) FROM %s.workflow_transition_history WHERE instance_id='" + instance + "'")).isEqualTo(1);
    }

    // 11. COMMIT_OUTCOME_UNKNOWN: lost COMMIT response after a durable commit, and failure before commit.
    @Test
    void lostCommitResponseIsCommitOutcomeUnknownAlthoughTheWriteIsDurable() throws Exception {
        String instance = instance("tenant-a", "leave_request", ALICE, acl(ALICE, "read", "transition"));
        var lossy = new PostgresAuthorizedWorkflowStore(commitFailing(runtime, true), schema);

        assertThatThrownBy(() -> new AuthorizedWorkflowService(() -> principal(ALICE), lossy, Clock.systemUTC())
                .transition("tenant-a", instance, "submit", 0)).isInstanceOfSatisfying(WorkflowException.class,
                failure -> assertThat(failure.code()).isEqualTo(WorkflowErrorCode.COMMIT_OUTCOME_UNKNOWN));
        assertThat(number("SELECT runtime_version FROM %s.workflow_instances WHERE instance_id='" + instance + "'")).isEqualTo(1);
    }

    @Test
    void commitFailureBeforeCommitIsAlsoUnknownAndLeavesNoWrite() throws Exception {
        String instance = instance("tenant-a", "leave_request", ALICE, acl(ALICE, "read", "transition"));
        var failing = new PostgresAuthorizedWorkflowStore(commitFailing(runtime, false), schema);

        assertThatThrownBy(() -> new AuthorizedWorkflowService(() -> principal(ALICE), failing, Clock.systemUTC())
                .transition("tenant-a", instance, "submit", 0)).isInstanceOfSatisfying(WorkflowException.class,
                failure -> assertThat(failure.code()).isEqualTo(WorkflowErrorCode.COMMIT_OUTCOME_UNKNOWN));
        assertUnchanged(instance);
    }

    // 12. Tenant/resource mapping: (type, id) together select the authoritative tenant.
    @Test
    void resourceTypeAndIdTogetherSelectTheAuthoritativeTenant() throws Exception {
        String id = "r-" + UUID.randomUUID();
        register("tenant-a", "leave_request", id, ALICE, acl(ALICE, "read", "transition"));
        register("tenant-b", "expense_claim", id, BOB, acl(BOB, "read", "transition"));
        String foreign = createInstance("expense_claim", id);

        assertDenied(() -> service(ALICE).get("tenant-a", foreign), "HIDDEN");
        assertDenied(() -> service(ALICE).transition("tenant-a", foreign, "submit", 0), "HIDDEN");
        assertUnchanged(foreign);
        assertThat(service(BOB).get("tenant-b", foreign).instanceId()).isEqualTo(foreign);

        ResourceAclSnapshot own = store.inTransaction(false,
                session -> session.read(new ResourceReference("leave_request", id), ALICE)).orElseThrow();
        ResourceAclSnapshot other = store.inTransaction(false,
                session -> session.read(new ResourceReference("expense_claim", id), ALICE)).orElseThrow();
        assertThat(own.tenantId()).isEqualTo("tenant-a");
        assertThat(own.grants()).containsExactlyInAnyOrder(WorkflowOperation.READ, WorkflowOperation.TRANSITION);
        assertThat(other.tenantId()).isEqualTo("tenant-b");
        assertThat(other.memberActive()).isFalse();
        assertThat(other.grants()).isEmpty();
        Optional<ResourceAclSnapshot> absent = store.inTransaction(false,
                session -> session.read(new ResourceReference("leave_request", "absent"), ALICE));
        assertThat(absent).isEmpty();
    }


    // 13. Coverage required by issue #9 beyond the R4 candidate suite.
    @Test
    void activationNeedsTheActivateGrantAndStaysTenantScoped() throws Exception {
        String id = "r-" + UUID.randomUUID();
        register("tenant-a", "leave_request", id, ALICE, acl(ALICE, "read", "activate"), acl(DAVE, "read"));
        String instance = "wf-" + UUID.randomUUID();
        new WorkflowRuntime(new PostgresWorkflowPersistence(db.migratorDataSource(), schema), Clock.systemUTC())
                .createInstance(instance, "leave-request", 1, new ResourceReference("leave_request", id));

        assertDenied(() -> service(DAVE).activate("tenant-a", instance), "FORBIDDEN");
        assertDenied(() -> service(BOB).activate("tenant-b", instance), "HIDDEN");
        assertThat(text("SELECT lifecycle FROM %s.workflow_instances WHERE instance_id='" + instance + "'"))
                .isEqualTo("NOT_STARTED");
        assertThat(service(ALICE).activate("tenant-a", instance).lifecycle().name()).isEqualTo("ACTIVE");
    }

    @Test
    void inactiveMembershipDoesNotCountForTenantResolution() throws Exception {
        String member = "oidc:moved-" + UUID.randomUUID();
        admin("INSERT INTO %s.tenant_memberships VALUES('tenant-a','" + member + "',false),('tenant-b','" + member + "',true)");
        String instance = instance("tenant-b", "leave_request", BOB, acl(member, "read"));

        assertThat(service(member).get(null, instance).instanceId()).isEqualTo(instance);
        assertDenied(() -> service(member).get("tenant-a", instance), "HIDDEN");
    }

    @Test
    void permittedHistoryReturnsTheRecordedActor() throws Exception {
        String instance = instance("tenant-a", "leave_request", ALICE, acl(ALICE, "read", "transition"));
        service(ALICE).transition("tenant-a", instance, "submit", 0);

        assertThat(service(ALICE).history("tenant-a", instance)).singleElement()
                .extracting(record -> record.actorReference().actorId()).isEqualTo(ALICE);
    }

    @Test
    void writeWaitingOnTheTenantLockSeesAMembershipRevocationCommittedMeanwhile() throws Exception {
        String member = "oidc:waiter-" + UUID.randomUUID();
        admin("INSERT INTO %s.tenant_memberships VALUES('tenant-a','" + member + "',true)");
        String instance = instance("tenant-a", "leave_request", ALICE, acl(member, "read", "transition"));

        assertThat(decisionAfterConcurrentPolicyEdit(
                "UPDATE %s.tenant_memberships SET active=false WHERE actor_id='" + member + "'",
                () -> service(member).transition("tenant-a", instance, "submit", 0))).isEqualTo("HIDDEN");
        assertUnchanged(instance);
    }

    @Test
    void writeWaitingOnTheTenantLockSeesATombstoneCommittedMeanwhile() throws Exception {
        String instance = instance("tenant-a", "leave_request", ALICE, acl(ALICE, "read", "transition"));

        assertThat(decisionAfterConcurrentPolicyEdit(
                "UPDATE %s.resource_registry SET lifecycle='TOMBSTONED', tombstoned_at=now() WHERE resource_id='"
                        + resourceOf(instance) + "'",
                () -> service(ALICE).transition("tenant-a", instance, "submit", 0))).isEqualTo("HIDDEN");
        assertUnchanged(instance);
    }

    @Test
    void readWaitingOnTheTenantLockSeesAGrantRevocationCommittedMeanwhile() throws Exception {
        String instance = instance("tenant-a", "leave_request", ALICE, acl(DAVE, "read"));

        assertThat(decisionAfterConcurrentPolicyEdit(
                "UPDATE %s.resource_acl SET granted=false WHERE actor_id='" + DAVE + "' AND resource_id='"
                        + resourceOf(instance) + "'",
                () -> service(DAVE).get("tenant-a", instance))).isEqualTo("HIDDEN");
    }

    @Test
    void runtimeRoleCannotWritePolicyFactsHistoryOrSchema() throws Exception {
        String resource = resourceOf(instance("tenant-a", "leave_request", ALICE, acl(ALICE, "read")));
        List<String> attempts = List.of(
                "INSERT INTO %s.resource_acl VALUES('tenant-a','leave_request','" + resource + "','" + DAVE
                        + "','workflow:transition',true)",
                "UPDATE %s.resource_acl SET granted=true",
                "INSERT INTO %s.tenant_memberships VALUES('tenant-b','" + ALICE + "',true)",
                "UPDATE %s.tenant_memberships SET active=true",
                "UPDATE %s.resource_registry SET owner_actor_id='" + ALICE + "'",
                "INSERT INTO %s.tenant_guards VALUES('tenant-z',0)",
                "UPDATE %s.workflow_definition_bindings SET active=true",
                "DELETE FROM %s.workflow_transition_history",
                "UPDATE %s.workflow_transition_history SET actor_id='forged'",
                "INSERT INTO %s.workflow_instances(instance_id) VALUES('forged')",
                "DELETE FROM %s.workflow_instances",
                "TRUNCATE %s.resource_acl",
                "CREATE TABLE %s.forged(x int)");
        for (String attempt : attempts) {
            try (var c = db.runtime()) {
                assertThatThrownBy(() -> sql(c, attempt.formatted(schema))).as(attempt)
                        .isInstanceOfSatisfying(SQLException.class,
                                failure -> assertThat(failure.getSQLState()).isEqualTo("42501"));
            }
        }
    }

    @Test
    void providerFailuresAreSanitizedUnavailableWithoutMutation() throws Exception {
        String instance = instance("tenant-a", "leave_request", ALICE, acl(ALICE, "read", "transition"));
        admin("REVOKE SELECT ON %s.tenant_memberships FROM " + runtimeRole);
        try {
            assertSanitizedUnavailable(() -> service(ALICE).transition("tenant-a", instance, "submit", 0));
        } finally {
            admin("GRANT SELECT ON %s.tenant_memberships TO " + runtimeRole);
        }
        var unreachable = new PostgresAuthorizedWorkflowStore(
                new DriverManagerDataSource("jdbc:postgresql://127.0.0.1:1/unreachable", "none", "none"), schema);
        var offline = new AuthorizedWorkflowService(() -> principal(ALICE), unreachable, Clock.systemUTC());
        assertSanitizedUnavailable(() -> offline.get("tenant-a", instance));
        assertSanitizedUnavailable(() -> offline.transition("tenant-a", instance, "submit", 0));
        assertUnchanged(instance);
    }

    @Test
    void concurrentWritesToDifferentInstancesOfOneTenantAllSucceed() throws Exception {
        List<String> instances = new ArrayList<>();
        for (int i = 0; i < 6; i++) instances.add(instance("tenant-a", "leave_request", ALICE, acl(ALICE, "read", "transition")));
        var start = new CountDownLatch(1);
        List<CompletableFuture<String>> attempts = new ArrayList<>();
        for (String instance : instances) {
            attempts.add(CompletableFuture.supplyAsync(() -> {
                await(start);
                try {
                    service(ALICE).transition("tenant-a", instance, "submit", 0);
                    return "OK";
                } catch (RuntimeException failure) {
                    return failure.getClass().getSimpleName() + ":" + failure.getMessage();
                }
            }));
        }
        start.countDown();
        List<String> outcomes = new ArrayList<>();
        for (var attempt : attempts) outcomes.add(attempt.get(30, TimeUnit.SECONDS));

        assertThat(outcomes).containsOnly("OK");
    }

    /** Holds an uncommitted policy edit, lets the call block on the tenant lock, then commits the edit. */
    private String decisionAfterConcurrentPolicyEdit(String edit, Runnable call) throws Exception {
        try (var policy = admin()) {
            policy.setAutoCommit(false);
            sql(policy, edit.formatted(schema));
            var attempt = CompletableFuture.supplyAsync(() -> {
                try {
                    call.run();
                    return "ALLOWED";
                } catch (WorkflowAccessException denied) {
                    return denied.decision().name();
                }
            });
            waitForRuntimeLockWait();
            policy.commit();
            return attempt.get(10, TimeUnit.SECONDS);
        }
    }

    private static void assertSanitizedUnavailable(Runnable call) {
        assertThatThrownBy(call::run).isInstanceOfSatisfying(WorkflowAccessException.class, failure -> {
            assertThat(failure.getMessage()).isEqualTo("UNAVAILABLE");
            assertThat(failure.getCause()).isNull();
            assertThat(failure.getSuppressed()).isEmpty();
        });
    }


    // ---- fixtures ----

    private record Acl(String actor, List<String> operations) {}

    private static Acl acl(String actor, String... operations) {
        return new Acl(actor, List.of(operations));
    }

    private String instance(String tenant, String resourceType, String owner, Acl... grants) throws Exception {
        String id = "r-" + UUID.randomUUID();
        register(tenant, resourceType, id, owner, grants);
        return createInstance(resourceType, id);
    }

    private void register(String tenant, String type, String id, String owner, Acl... grants) throws Exception {
        try (var c = admin()) {
            c.setAutoCommit(false);
            sql(c, "INSERT INTO " + schema + ".resource_registry(resource_type,resource_id,tenant_id,owner_actor_id,lifecycle) VALUES('"
                    + type + "','" + id + "','" + tenant + "','" + owner + "','ACTIVE')");
            for (Acl grant : grants) for (String operation : grant.operations()) {
                sql(c, "INSERT INTO " + schema + ".resource_acl VALUES('" + tenant + "','" + type + "','" + id + "','"
                        + grant.actor() + "','workflow:" + operation + "',true)");
            }
            c.commit();
        }
    }

    private String createInstance(String type, String resourceId) {
        String instanceId = "wf-" + UUID.randomUUID();
        var runtimeWorkflow = new WorkflowRuntime(new PostgresWorkflowPersistence(db.migratorDataSource(), schema), Clock.systemUTC());
        runtimeWorkflow.createInstance(instanceId, "leave-request", 1, new ResourceReference(type, resourceId));
        runtimeWorkflow.activateInstance(instanceId);
        return instanceId;
    }

    private String resourceOf(String instance) throws SQLException {
        return text("SELECT resource_id FROM %s.workflow_instances WHERE instance_id='" + instance + "'");
    }

    private AuthorizedWorkflowService service(String actor) {
        return new AuthorizedWorkflowService(() -> principal(actor), store, Clock.systemUTC());
    }

    private static AuthenticatedPrincipal principal(String actor) {
        return new AuthenticatedPrincipal(actor, null,
                ALL.stream().map(Authority::new).collect(Collectors.toSet()), true);
    }

    private void assertUnchanged(String instance) throws SQLException {
        assertThat(number("SELECT runtime_version FROM %s.workflow_instances WHERE instance_id='" + instance + "'")).isZero();
        assertThat(text("SELECT current_state FROM %s.workflow_instances WHERE instance_id='" + instance + "'")).isEqualTo("draft");
        assertThat(number("SELECT count(*) FROM %s.workflow_transition_history WHERE instance_id='" + instance + "'")).isZero();
    }

    private static void assertDenied(Runnable call, String decision) {
        assertThatThrownBy(call::run).isInstanceOfSatisfying(WorkflowAccessException.class,
                failure -> assertThat(failure.decision().name()).isEqualTo(decision));
    }

    private void waitForRuntimeLockWait() throws Exception {
        for (int i = 0; i < 100; i++) {
            if (number("SELECT count(*) FROM pg_stat_activity WHERE usename='" + runtimeRole + "' AND wait_event_type='Lock'") > 0) return;
            Thread.sleep(50);
        }
        throw new AssertionError("runtime transaction never waited for the tenant lock");
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(10, TimeUnit.SECONDS)) throw new AssertionError("latch timeout");
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new AssertionError(interrupted);
        }
    }

    /** Wraps COMMIT: either commits then loses the response, or fails without committing. */
    private static DataSource commitFailing(DataSource delegate, boolean commitBeforeFailing) {
        return (DataSource) Proxy.newProxyInstance(DataSource.class.getClassLoader(), new Class<?>[]{DataSource.class},
                (proxy, method, args) -> {
                    Object result = invoke(delegate, method, args);
                    if (!(result instanceof Connection connection)) return result;
                    return Proxy.newProxyInstance(Connection.class.getClassLoader(), new Class<?>[]{Connection.class},
                            (p, m, a) -> {
                                if (m.getName().equals("commit")) {
                                    if (commitBeforeFailing) connection.commit();
                                    throw new SQLException("simulated lost COMMIT response");
                                }
                                return invoke(connection, m, a);
                            });
                });
    }

    private static Object invoke(Object target, java.lang.reflect.Method method, Object[] args) throws Throwable {
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException failure) {
            throw failure.getCause();
        }
    }


    private Connection admin() throws SQLException {
        String secret = System.getenv("HELPDESK_DISPOSABLE_PASSWORD");
        return DriverManager.getConnection(url, "helpdesk_test", secret == null ? "" : secret);
    }

    private void admin(String statement) throws SQLException {
        try (var c = admin()) {
            sql(c, statement.formatted(schema));
        }
    }

    private long number(String query) throws SQLException {
        try (var c = admin()) {
            return number(c, query.formatted(schema));
        }
    }

    private String text(String query) throws SQLException {
        try (var c = admin(); var s = c.createStatement(); var r = s.executeQuery(query.formatted(schema))) {
            assertThat(r.next()).isTrue();
            return r.getString(1);
        }
    }

    private static void sql(Connection c, String sql) throws SQLException {
        try (var s = c.createStatement()) {
            s.execute(sql);
        }
    }

    private static long number(Connection c, String sql) throws SQLException {
        try (var s = c.createStatement(); var r = s.executeQuery(sql)) {
            r.next();
            return r.getLong(1);
        }
    }
}
