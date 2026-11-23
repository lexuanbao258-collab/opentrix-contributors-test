// SPDX-FileCopyrightText: 2026 TRICORE contributors
//
// SPDX-License-Identifier: Apache-2.0

package com.tricore.dxos.application.workflow;

import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tricore.dxos.application.authorization.WorkflowAccessException;
import com.tricore.dxos.application.authorization.WorkflowAclSnapshotReader.ResourceAclSnapshot;
import com.tricore.dxos.application.authorization.WorkflowOperation;
import com.tricore.dxos.application.identity.CurrentPrincipal;
import com.tricore.dxos.core.identity.AuthenticatedPrincipal;
import com.tricore.dxos.core.identity.Authority;
import com.tricore.dxos.core.workflow.ResourceReference;
import com.tricore.dxos.core.workflow.TransitionRecord;
import com.tricore.dxos.core.workflow.TransitionResult;
import com.tricore.dxos.core.workflow.WorkflowDefinition;
import com.tricore.dxos.core.workflow.WorkflowErrorCode;
import com.tricore.dxos.core.workflow.WorkflowException;
import com.tricore.dxos.core.workflow.WorkflowInstance;
import com.tricore.dxos.core.workflow.WorkflowLifecycle;
import com.tricore.dxos.core.workflow.WorkflowPersistencePort;
import com.tricore.dxos.core.workflow.WorkflowTransition;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit guarantees only: the in-memory store models one transaction with rollback on exception,
 * but proves neither PostgreSQL atomicity, row/tenant locking nor database-level tenant isolation.
 */
class AuthorizedWorkflowServiceTest {
    private static final Instant T0 = Instant.parse("2026-11-21T00:00:00Z");
    private static final WorkflowDefinition DEFINITION = new WorkflowDefinition("leave-request", 1, "draft",
            Set.of("draft", "submitted"), Set.of(new WorkflowTransition("submit", "draft", "submitted")));
    private static final ResourceReference RESOURCE = new ResourceReference("leave_request", "r-1");
    private static final String ALICE = "oidc:alice";
    private static final String BOB = "oidc:bob";
    private static final Set<String> ALL_AUTHORITIES =
            Set.of("workflow:create", "workflow:activate", "workflow:transition", "workflow:read");

    private final FakeStore store = new FakeStore();
    private AuthenticatedPrincipal principal = principal(ALICE, ALL_AUTHORITIES);
    private final CurrentPrincipal currentPrincipal = () -> principal;
    private final AuthorizedWorkflowService service = new AuthorizedWorkflowService(
            currentPrincipal, store, Clock.fixed(T0.plusSeconds(60), ZoneOffset.UTC));

    // 1. Verified principal with permitted operation.
    @Test
    void permittedTransitionRecordsTheVerifiedSubjectAndCommits() {
        store.activeInstance("i-1", RESOURCE);
        store.member(ALICE, "tenant-a");
        store.acl(RESOURCE, ALICE, "tenant-a", false, WorkflowOperation.READ, WorkflowOperation.TRANSITION);

        TransitionResult result = service.transition("tenant-a", "i-1", "submit", 0);

        assertThat(result.instance().currentState()).isEqualTo("submitted");
        assertThat(store.workflow.loadInstance("i-1").runtimeVersion()).isEqualTo(1);
        assertThat(store.workflow.loadHistory("i-1")).singleElement()
                .extracting(record -> record.actorReference().actorId()).isEqualTo(ALICE);
        assertThat(store.locks).containsExactly("tenant-a:exclusive");
    }

    @Test
    void permittedReadsUseASharedTenantLockAndResolveTheOnlyMembership() {
        store.activeInstance("i-1", RESOURCE);
        store.member(ALICE, "tenant-a");
        store.acl(RESOURCE, ALICE, "tenant-a", false, WorkflowOperation.READ);

        assertThat(service.get(null, "i-1").instanceId()).isEqualTo("i-1");
        assertThat(service.history(null, "i-1")).isEmpty();
        assertThat(store.locks).containsExactly("tenant-a:shared", "tenant-a:shared");
    }

    @Test
    void permittedActivationMovesNotStartedToActive() {
        store.notStartedInstance("i-1", RESOURCE);
        store.member(ALICE, "tenant-a");
        store.acl(RESOURCE, ALICE, "tenant-a", false, WorkflowOperation.READ, WorkflowOperation.ACTIVATE);

        assertThat(service.activate("tenant-a", "i-1").lifecycle()).isEqualTo(WorkflowLifecycle.ACTIVE);
    }

    // 2. Missing or invalid principal.
    @Test
    void missingVerifiedPrincipalFailsBeforeAnyTransaction() {
        CurrentPrincipal unauthenticated = () -> {
            throw new IllegalStateException("Verified authentication is required");
        };
        var unauthenticatedService = new AuthorizedWorkflowService(unauthenticated, store, Clock.systemUTC());
        store.activeInstance("i-1", RESOURCE);

        assertThatThrownBy(() -> unauthenticatedService.transition("tenant-a", "i-1", "submit", 0))
                .isInstanceOf(IllegalStateException.class);
        assertThat(store.transactions).isZero();
    }

    // 3. Principal without required authority.
    @Test
    void missingOperationAuthorityIsForbiddenAndDoesNotMutate() {
        principal = principal(ALICE, Set.of("workflow:read"));
        store.activeInstance("i-1", RESOURCE);
        store.member(ALICE, "tenant-a");
        store.acl(RESOURCE, ALICE, "tenant-a", false, WorkflowOperation.READ, WorkflowOperation.TRANSITION);

        assertDenied(() -> service.transition("tenant-a", "i-1", "submit", 0), "FORBIDDEN");
        assertUnchanged("i-1");
    }

    // 4. Principal outside the resource's tenant.
    @Test
    void resourceInAnotherTenantIsHiddenEvenWhenTheCallerAlsoBelongsToThatTenant() {
        store.activeInstance("i-1", RESOURCE);
        store.member(ALICE, "tenant-a");
        store.member(ALICE, "tenant-b");
        store.acl(RESOURCE, ALICE, "tenant-b", true, WorkflowOperation.values());

        assertDenied(() -> service.transition("tenant-a", "i-1", "submit", 0), "HIDDEN");
        assertDenied(() -> service.get("tenant-a", "i-1"), "HIDDEN");
        assertUnchanged("i-1");
    }

    @Test
    void crossTenantAndMissingInstancesAreIndistinguishable() {
        store.activeInstance("i-1", RESOURCE);
        store.member(ALICE, "tenant-a");
        store.acl(RESOURCE, ALICE, "tenant-b", true, WorkflowOperation.values());

        assertDenied(() -> service.get("tenant-a", "i-1"), "HIDDEN");
        assertDenied(() -> service.get("tenant-a", "does-not-exist"), "HIDDEN");
    }

    @Test
    void unverifiedTenantSelectionIsHiddenWithoutLockingThatTenant() {
        store.activeInstance("i-1", RESOURCE);
        store.member(ALICE, "tenant-a");
        store.acl(RESOURCE, ALICE, "tenant-b", true, WorkflowOperation.values());

        assertDenied(() -> service.transition("tenant-b", "i-1", "submit", 0), "HIDDEN");
        assertThat(store.locks).isEmpty();
        assertUnchanged("i-1");
    }

    @Test
    void callerWithoutAnyActiveMembershipIsHidden() {
        store.activeInstance("i-1", RESOURCE);

        assertDenied(() -> service.get(null, "i-1"), "HIDDEN");
    }

    @Test
    void inactiveMembershipInTheAclSnapshotIsHidden() {
        store.activeInstance("i-1", RESOURCE);
        store.member(ALICE, "tenant-a");
        store.aclSnapshots.put(RESOURCE.resourceId() + "|" + ALICE, new ResourceAclSnapshot(RESOURCE, ALICE,
                "tenant-a", true, false, true, EnumSet.allOf(WorkflowOperation.class), Set.of()));

        assertDenied(() -> service.get("tenant-a", "i-1"), "HIDDEN");
    }

    // 5. Principal without resource ACL permission.
    @Test
    void memberWithoutAnyGrantIsHidden() {
        store.activeInstance("i-1", RESOURCE);
        store.member(ALICE, "tenant-a");
        store.acl(RESOURCE, ALICE, "tenant-a", false);

        assertDenied(() -> service.get("tenant-a", "i-1"), "HIDDEN");
    }

    @Test
    void visibleResourceWithoutTheOperationGrantIsForbiddenAndDoesNotMutate() {
        store.activeInstance("i-1", RESOURCE);
        store.member(ALICE, "tenant-a");
        store.acl(RESOURCE, ALICE, "tenant-a", true, WorkflowOperation.READ);

        assertDenied(() -> service.transition("tenant-a", "i-1", "submit", 0), "FORBIDDEN");
        assertUnchanged("i-1");
    }

    @Test
    void transitionGrantWithoutReadGrantIsForbiddenBecauseTheResultDisclosesState() {
        store.activeInstance("i-1", RESOURCE);
        store.member(ALICE, "tenant-a");
        store.acl(RESOURCE, ALICE, "tenant-a", false, WorkflowOperation.TRANSITION);

        assertDenied(() -> service.transition("tenant-a", "i-1", "submit", 0), "FORBIDDEN");
        assertUnchanged("i-1");
    }

    // 6. Attempts to spoof actor identity.
    @Test
    void displayNameCannotSelectAnotherActorsAcl() {
        principal = new AuthenticatedPrincipal(ALICE, BOB, authorities(ALL_AUTHORITIES), true);
        store.activeInstance("i-1", RESOURCE);
        store.member(ALICE, "tenant-a");
        store.member(BOB, "tenant-a");
        store.acl(RESOURCE, BOB, "tenant-a", true, WorkflowOperation.values());

        assertDenied(() -> service.transition("tenant-a", "i-1", "submit", 0), "HIDDEN");
        assertUnchanged("i-1");
    }

    @Test
    void aclSnapshotEchoingAnotherActorFailsClosed() {
        store.activeInstance("i-1", RESOURCE);
        store.member(ALICE, "tenant-a");
        store.aclSnapshots.put(RESOURCE.resourceId() + "|" + ALICE, new ResourceAclSnapshot(RESOURCE, BOB,
                "tenant-a", true, true, true, EnumSet.allOf(WorkflowOperation.class), Set.of()));

        assertDenied(() -> service.transition("tenant-a", "i-1", "submit", 0), "UNAVAILABLE");
        assertUnchanged("i-1");
    }

    @Test
    void publicApiAcceptsNoCallerSuppliedActorPrincipalOrAuthority() {
        List<Class<?>> forbidden = List.of(AuthenticatedPrincipal.class, Authority.class,
                com.tricore.dxos.core.workflow.ActorReference.class, CurrentPrincipal.class);
        for (Method method : AuthorizedWorkflowService.class.getDeclaredMethods()) {
            if (Modifier.isPublic(method.getModifiers())) {
                assertThat(Arrays.asList(method.getParameterTypes())).doesNotContainAnyElementsOf(forbidden);
            }
        }
    }

    // 7. Ambiguous tenant membership.
    @Test
    void multipleMembershipsWithoutSelectionFailBeforeLockingOrLoading() {
        store.activeInstance("i-1", RESOURCE);
        store.member(ALICE, "tenant-a");
        store.member(ALICE, "tenant-b");
        store.acl(RESOURCE, ALICE, "tenant-a", true, WorkflowOperation.values());

        assertThatThrownBy(() -> service.transition(null, "i-1", "submit", 0))
                .isInstanceOf(TenantSelectionRequiredException.class)
                .hasMessageNotContaining("tenant-a").hasMessageNotContaining("tenant-b");
        assertThat(store.locks).isEmpty();
        assertThat(store.instanceLoads).isZero();
        assertUnchanged("i-1");
    }

    @Test
    void explicitSelectionAmongMultipleMembershipsIsVerifiedThenUsed() {
        store.activeInstance("i-1", RESOURCE);
        store.member(ALICE, "tenant-a");
        store.member(ALICE, "tenant-b");
        store.acl(RESOURCE, ALICE, "tenant-a", false, WorkflowOperation.READ, WorkflowOperation.TRANSITION);

        service.transition("tenant-a", "i-1", "submit", 0);

        assertThat(store.locks).containsExactly("tenant-a:exclusive");
    }

    // 8. Authorization dependency unavailable.
    @Test
    void aclLookupFailureIsUnavailableAndDoesNotMutate() {
        store.activeInstance("i-1", RESOURCE);
        store.member(ALICE, "tenant-a");
        store.aclFailure = new RuntimeException("connection reset with SQL details");

        assertDenied(() -> service.transition("tenant-a", "i-1", "submit", 0), "UNAVAILABLE");
        assertUnchanged("i-1");
    }

    @Test
    void membershipLookupFailureIsUnavailableAndDoesNotLeakProviderDetails() {
        store.activeInstance("i-1", RESOURCE);
        store.member(ALICE, "tenant-a");
        store.acl(RESOURCE, ALICE, "tenant-a", false, WorkflowOperation.READ, WorkflowOperation.TRANSITION);
        store.membershipFailure = new RuntimeException("connection reset with SQL details");

        assertDenied(() -> service.transition("tenant-a", "i-1", "submit", 0), "UNAVAILABLE");
        assertThat(store.locks).isEmpty();
        assertUnchanged("i-1");
    }

    @Test
    void tenantLockFailureIsUnavailableAndDoesNotLeakProviderDetails() {
        store.activeInstance("i-1", RESOURCE);
        store.member(ALICE, "tenant-a");
        store.acl(RESOURCE, ALICE, "tenant-a", false, WorkflowOperation.READ, WorkflowOperation.TRANSITION);
        store.lockFailure = new RuntimeException("lock timeout with SQL details");

        assertDenied(() -> service.transition("tenant-a", "i-1", "submit", 0), "UNAVAILABLE");
        assertThat(store.instanceLoads).isZero();
        assertUnchanged("i-1");
    }

    @Test
    void nullAclAnswerIsUnavailable() {
        store.activeInstance("i-1", RESOURCE);
        store.member(ALICE, "tenant-a");
        store.nullAcl = true;

        assertDenied(() -> service.get("tenant-a", "i-1"), "UNAVAILABLE");
    }

    @Test
    void unknownTenantGuardIsHidden() {
        store.activeInstance("i-1", RESOURCE);
        store.member(ALICE, "tenant-a");
        store.acl(RESOURCE, ALICE, "tenant-a", true, WorkflowOperation.values());
        store.missingTenantGuards = true;

        assertDenied(() -> service.get("tenant-a", "i-1"), "HIDDEN");
    }

    // 9/10. Denied operations do not mutate; transaction/error contracts are preserved.
    @Test
    void staleExpectedVersionPropagatesVersionConflictWithoutMutation() {
        store.activeInstance("i-1", RESOURCE);
        store.member(ALICE, "tenant-a");
        store.acl(RESOURCE, ALICE, "tenant-a", false, WorkflowOperation.READ, WorkflowOperation.TRANSITION);

        assertThatThrownBy(() -> service.transition("tenant-a", "i-1", "submit", 5))
                .isInstanceOfSatisfying(WorkflowException.class,
                        failure -> assertThat(failure.code()).isEqualTo(WorkflowErrorCode.VERSION_CONFLICT));
        assertUnchanged("i-1");
    }

    @Test
    void commitOutcomeUnknownPropagatesUnchangedAndIsNotRetried() {
        store.activeInstance("i-1", RESOURCE);
        store.member(ALICE, "tenant-a");
        store.acl(RESOURCE, ALICE, "tenant-a", false, WorkflowOperation.READ, WorkflowOperation.TRANSITION);
        store.loseNextCommitResponse = true;

        assertThatThrownBy(() -> service.transition("tenant-a", "i-1", "submit", 0))
                .isInstanceOfSatisfying(WorkflowException.class, failure ->
                        assertThat(failure.code()).isEqualTo(WorkflowErrorCode.COMMIT_OUTCOME_UNKNOWN));
        assertThat(store.transactions).isEqualTo(1);
        // The fake committed before losing the response: callers must reconcile, never blindly retry.
        assertThat(store.workflow.loadInstance("i-1").runtimeVersion()).isEqualTo(1);
    }

    @Test
    void authorizationAndWriteShareExactlyOneTransaction() {
        store.activeInstance("i-1", RESOURCE);
        store.member(ALICE, "tenant-a");
        store.acl(RESOURCE, ALICE, "tenant-a", false, WorkflowOperation.READ, WorkflowOperation.TRANSITION);

        service.transition("tenant-a", "i-1", "submit", 0);

        assertThat(store.transactions).isEqualTo(1);
        assertThat(store.writeTransactions).isEqualTo(1);
    }

    @Test
    void applicationWorkflowPackageStaysFreeOfInfrastructureGatewayAndSpring() {
        var classes = new ClassFileImporter().withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages("com.tricore.dxos.application.workflow");
        assertThat(classes.contain(AuthorizedWorkflowService.class)).isTrue();
        noClasses().should().dependOnClassesThat().resideInAnyPackage(
                "com.tricore.dxos.infrastructure..", "com.tricore.dxos.gateway..", "org.springframework..",
                "java.sql..").check(classes);
    }

    private void assertUnchanged(String instanceId) {
        assertThat(store.workflow.loadInstance(instanceId).runtimeVersion()).isZero();
        assertThat(store.workflow.loadHistory(instanceId)).isEmpty();
    }

    private static void assertDenied(Runnable call, String decision) {
        assertThatThrownBy(call::run).isInstanceOf(WorkflowAccessException.class).hasMessage(decision);
    }

    private static AuthenticatedPrincipal principal(String subject, Set<String> authorities) {
        return new AuthenticatedPrincipal(subject, null, authorities(authorities), true);
    }

    private static Set<Authority> authorities(Set<String> values) {
        Set<Authority> result = new java.util.HashSet<>();
        values.forEach(value -> result.add(new Authority(value)));
        return result;
    }

    /** Models one transaction: writes are discarded when the callback throws. */
    private static final class FakeStore implements AuthorizedWorkflowStore {
        final FakeWorkflow workflow = new FakeWorkflow();
        final Map<String, Set<String>> memberships = new HashMap<>();
        final Map<String, ResourceAclSnapshot> aclSnapshots = new HashMap<>();
        final List<String> locks = new ArrayList<>();
        RuntimeException aclFailure;
        RuntimeException membershipFailure;
        RuntimeException lockFailure;
        boolean nullAcl;
        boolean missingTenantGuards;
        boolean loseNextCommitResponse;
        int transactions;
        int writeTransactions;
        int instanceLoads;

        void member(String actor, String tenant) {
            memberships.computeIfAbsent(actor, key -> new java.util.HashSet<>()).add(tenant);
        }

        void acl(ResourceReference resource, String actor, String tenant, boolean owner, WorkflowOperation... grants) {
            aclSnapshots.put(resource.resourceId() + "|" + actor, new ResourceAclSnapshot(resource, actor, tenant,
                    true, true, owner, grants.length == 0 ? Set.of() : EnumSet.copyOf(List.of(grants)), Set.of()));
        }

        void notStartedInstance(String id, ResourceReference resource) {
            workflow.instances.put(id, WorkflowInstance.notStarted(id, DEFINITION, resource, T0));
            workflow.histories.put(id, List.of());
        }

        void activeInstance(String id, ResourceReference resource) {
            workflow.instances.put(id, WorkflowInstance.notStarted(id, DEFINITION, resource, T0).activate(DEFINITION, T0));
            workflow.histories.put(id, List.of());
        }

        @Override
        public <T> T inTransaction(boolean write, Function<Session, T> work) {
            transactions++;
            if (write) writeTransactions++;
            var savedInstances = new HashMap<>(workflow.instances);
            var savedHistories = new HashMap<>(workflow.histories);
            T result;
            try {
                result = work.apply(new FakeSession());
            } catch (RuntimeException failure) {
                workflow.instances.clear();
                workflow.instances.putAll(savedInstances);
                workflow.histories.clear();
                workflow.histories.putAll(savedHistories);
                throw failure;
            }
            if (write && loseNextCommitResponse) {
                loseNextCommitResponse = false;
                throw new WorkflowException(WorkflowErrorCode.COMMIT_OUTCOME_UNKNOWN);
            }
            return result;
        }

        private final class FakeSession implements Session {
            @Override
            public Set<String> activeTenantIds(String verifiedActorId) {
                if (membershipFailure != null) throw membershipFailure;
                return Set.copyOf(memberships.getOrDefault(verifiedActorId, Set.of()));
            }

            @Override
            public boolean lockTenant(String tenantId, boolean exclusive) {
                if (lockFailure != null) throw lockFailure;
                locks.add(tenantId + (exclusive ? ":exclusive" : ":shared"));
                return !missingTenantGuards;
            }

            @Override
            public WorkflowPersistencePort workflow() {
                return new CountingWorkflow();
            }

            @Override
            public Optional<ResourceAclSnapshot> read(ResourceReference resource, String verifiedActorId) {
                if (aclFailure != null) throw aclFailure;
                if (nullAcl) return null;
                return Optional.ofNullable(aclSnapshots.get(resource.resourceId() + "|" + verifiedActorId));
            }
        }

        private final class CountingWorkflow implements WorkflowPersistencePort {
            @Override public WorkflowDefinition loadDefinition(String id, long version) {
                return workflow.loadDefinition(id, version);
            }
            @Override public WorkflowInstance createInstance(WorkflowInstance initial) {
                return workflow.createInstance(initial);
            }
            @Override public WorkflowInstance commitActivation(WorkflowInstance expected, WorkflowInstance activated) {
                return workflow.commitActivation(expected, activated);
            }
            @Override public WorkflowInstance loadInstance(String instanceId) {
                instanceLoads++;
                return workflow.loadInstance(instanceId);
            }
            @Override public List<TransitionRecord> loadHistory(String instanceId) {
                return workflow.loadHistory(instanceId);
            }
            @Override public TransitionResult commitTransition(TransitionResult transition) {
                return workflow.commitTransition(transition);
            }
        }
    }

    /** Minimal contract fake; persists only within the enclosing FakeStore transaction. */
    private static final class FakeWorkflow implements WorkflowPersistencePort {
        final Map<String, WorkflowInstance> instances = new HashMap<>();
        final Map<String, List<TransitionRecord>> histories = new HashMap<>();

        @Override
        public WorkflowDefinition loadDefinition(String id, long version) {
            if (!DEFINITION.definitionId().equals(id) || DEFINITION.definitionVersion() != version) {
                throw new WorkflowException(WorkflowErrorCode.DEFINITION_NOT_FOUND);
            }
            return DEFINITION;
        }

        @Override
        public WorkflowInstance createInstance(WorkflowInstance initial) {
            throw new UnsupportedOperationException("creation is outside this slice");
        }

        @Override
        public WorkflowInstance commitActivation(WorkflowInstance expected, WorkflowInstance activated) {
            WorkflowInstance stored = loadInstance(expected.instanceId());
            if (stored.runtimeVersion() != expected.runtimeVersion() || stored.lifecycle() != expected.lifecycle()) {
                throw new WorkflowException(WorkflowErrorCode.VERSION_CONFLICT);
            }
            instances.put(activated.instanceId(), activated);
            return activated;
        }

        @Override
        public WorkflowInstance loadInstance(String instanceId) {
            WorkflowInstance instance = instances.get(instanceId);
            if (instance == null) throw new WorkflowException(WorkflowErrorCode.INSTANCE_NOT_FOUND);
            return instance;
        }

        @Override
        public List<TransitionRecord> loadHistory(String instanceId) {
            loadInstance(instanceId);
            return List.copyOf(histories.get(instanceId));
        }

        @Override
        public TransitionResult commitTransition(TransitionResult transition) {
            WorkflowInstance stored = loadInstance(transition.previousInstance().instanceId());
            if (stored.runtimeVersion() != transition.expectedVersion()) {
                throw new WorkflowException(WorkflowErrorCode.VERSION_CONFLICT);
            }
            instances.put(stored.instanceId(), transition.instance());
            List<TransitionRecord> history = new ArrayList<>(histories.get(stored.instanceId()));
            history.add(transition.record());
            histories.put(stored.instanceId(), List.copyOf(history));
            return transition;
        }
    }
}
