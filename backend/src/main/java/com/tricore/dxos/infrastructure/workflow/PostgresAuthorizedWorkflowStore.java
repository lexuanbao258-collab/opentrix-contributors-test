// SPDX-FileCopyrightText: 2026 TRICORE contributors
//
// SPDX-License-Identifier: Apache-2.0

package com.tricore.dxos.infrastructure.workflow;

import com.tricore.dxos.application.authorization.WorkflowAccessException;
import com.tricore.dxos.application.authorization.WorkflowAclSnapshotReader.DefinitionBinding;
import com.tricore.dxos.application.authorization.WorkflowAclSnapshotReader.ResourceAclSnapshot;
import com.tricore.dxos.application.authorization.WorkflowOperation;
import com.tricore.dxos.application.workflow.AuthorizedWorkflowStore;
import com.tricore.dxos.application.workflow.TenantSelectionRequiredException;
import com.tricore.dxos.core.workflow.ResourceReference;
import com.tricore.dxos.core.workflow.TransitionRecord;
import com.tricore.dxos.core.workflow.TransitionResult;
import com.tricore.dxos.core.workflow.WorkflowDefinition;
import com.tricore.dxos.core.workflow.WorkflowInstance;
import com.tricore.dxos.core.workflow.WorkflowPersistencePort;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

/**
 * PostgreSQL {@link AuthorizedWorkflowStore} over the guarded Workflow transaction
 * (READ COMMITTED, lock/statement timeouts, sanitized failures, COMMIT_OUTCOME_UNKNOWN after COMMIT).
 *
 * <p>Requires the policy relations and tenant-lock triggers of the {@code db/workflow-policy} V5
 * candidate (outside {@code db/migration}). V5 is not production-approved, so this adapter is
 * deliberately not a Spring bean. The tenant lock is the {@code tenant_guards} row that those
 * policy-edit triggers also lock.
 */
public final class PostgresAuthorizedWorkflowStore implements AuthorizedWorkflowStore {
    private static final String RESOURCE_SNAPSHOT = """
            SELECT r.tenant_id, r.owner_actor_id, r.lifecycle, m.active
            FROM %s.resource_registry r
            LEFT JOIN %s.tenant_memberships m ON m.tenant_id = r.tenant_id AND m.actor_id = ?
            WHERE r.resource_type = ? AND r.resource_id = ?
            """;

    private final PostgresWorkflowPersistence persistence;
    private final String schema;

    public PostgresAuthorizedWorkflowStore(DataSource dataSource, String schema) {
        // One schema value for both the persistence adapter and the policy queries.
        this.persistence = new PostgresWorkflowPersistence(dataSource, schema);
        this.schema = new WorkflowSchema(schema).quoted();
    }

    @Override
    public <T> T inTransaction(boolean write, Function<Session, T> work) {
        Objects.requireNonNull(work, "work");
        TenantSelectionRequiredException[] selection = new TenantSelectionRequiredException[1];
        try {
            return persistence.guardedTransaction(write, connection -> {
                JdbcSession session = new JdbcSession(connection);
                try {
                    return work.apply(session);
                } catch (TenantSelectionRequiredException required) {
                    selection[0] = required;
                    throw required;
                } finally {
                    session.active = false;
                }
            });
        } catch (WorkflowAccessException failure) {
            // The guarded transaction sanitizes unknown exceptions to UNAVAILABLE after rolling back;
            // restore the caller-actionable selection error. Commit-unknown outcomes are never rewritten.
            if (selection[0] != null) throw selection[0];
            throw failure;
        }
    }

    private final class JdbcSession implements Session {
        private final Connection connection;
        private boolean active = true;

        private JdbcSession(Connection connection) {
            this.connection = connection;
        }

        @Override
        public Set<String> activeTenantIds(String verifiedActorId) {
            requireActive();
            return sql(() -> {
                Set<String> tenants = new HashSet<>();
                try (var statement = prepare("SELECT tenant_id FROM %s.tenant_memberships WHERE actor_id = ? AND active",
                        verifiedActorId); var rows = statement.executeQuery()) {
                    while (rows.next()) tenants.add(rows.getString(1));
                }
                return Set.copyOf(tenants);
            });
        }

        @Override
        public boolean lockTenant(String tenantId, boolean exclusive) {
            requireActive();
            return sql(() -> {
                try (var statement = prepare("SELECT tenant_id FROM %s.tenant_guards WHERE tenant_id = ?"
                        + (exclusive ? " FOR UPDATE" : " FOR SHARE"), tenantId); var rows = statement.executeQuery()) {
                    return rows.next();
                }
            });
        }

        @Override
        public Optional<ResourceAclSnapshot> read(ResourceReference resource, String verifiedActorId) {
            requireActive();
            return sql(() -> {
                String tenant;
                String owner;
                boolean resourceActive;
                boolean memberActive;
                try (var statement = prepare(RESOURCE_SNAPSHOT, verifiedActorId, resource.resourceType(),
                        resource.resourceId()); var rows = statement.executeQuery()) {
                    if (!rows.next()) return Optional.empty();
                    tenant = rows.getString(1);
                    owner = rows.getString(2);
                    resourceActive = "ACTIVE".equals(rows.getString(3));
                    memberActive = rows.getBoolean(4); // NULL (no membership) reads as false
                }
                Set<WorkflowOperation> grants = EnumSet.noneOf(WorkflowOperation.class);
                try (var statement = prepare("""
                        SELECT operation FROM %s.resource_acl
                        WHERE tenant_id = ? AND resource_type = ? AND resource_id = ? AND actor_id = ? AND granted
                        """, tenant, resource.resourceType(), resource.resourceId(), verifiedActorId);
                     var rows = statement.executeQuery()) {
                    while (rows.next()) grants.add(operation(rows.getString(1)));
                }
                Set<DefinitionBinding> bindings = new HashSet<>();
                try (var statement = prepare("""
                        SELECT definition_id, definition_version FROM %s.workflow_definition_bindings
                        WHERE tenant_id = ? AND resource_type = ? AND active
                        """, tenant, resource.resourceType()); var rows = statement.executeQuery()) {
                    while (rows.next()) bindings.add(new DefinitionBinding(rows.getString(1), rows.getLong(2)));
                }
                return Optional.of(new ResourceAclSnapshot(resource, verifiedActorId, tenant, resourceActive,
                        memberActive, verifiedActorId.equals(owner), grants, bindings));
            });
        }

        @Override
        public WorkflowPersistencePort workflow() {
            requireActive();
            return new WorkflowPersistencePort() {
                @Override
                public WorkflowDefinition loadDefinition(String definitionId, long definitionVersion) {
                    requireActive();
                    return sql(() -> persistence.loadDefinition(connection, definitionId, definitionVersion));
                }

                @Override
                public WorkflowInstance createInstance(WorkflowInstance initial) {
                    requireActive();
                    return sql(() -> persistence.createInstance(connection, initial));
                }

                @Override
                public WorkflowInstance commitActivation(WorkflowInstance expected, WorkflowInstance activated) {
                    requireActive();
                    return sql(() -> persistence.commitActivation(connection, expected, activated));
                }

                @Override
                public WorkflowInstance loadInstance(String instanceId) {
                    requireActive();
                    return sql(() -> persistence.loadInstance(connection, instanceId));
                }

                @Override
                public List<TransitionRecord> loadHistory(String instanceId) {
                    requireActive();
                    return sql(() -> persistence.loadHistory(connection, instanceId));
                }

                @Override
                public TransitionResult commitTransition(TransitionResult transition) {
                    requireActive();
                    return sql(() -> persistence.commitTransition(connection, transition));
                }
            };
        }

        private void requireActive() {
            if (!active) throw new IllegalStateException("Session used outside its transaction");
        }

        private PreparedStatement prepare(String sql, Object... values) throws SQLException {
            PreparedStatement statement = connection.prepareStatement(sql.replace("%s", schema));
            try {
                for (int i = 0; i < values.length; i++) statement.setObject(i + 1, values[i]);
                return statement;
            } catch (SQLException | RuntimeException failure) {
                try { statement.close(); } catch (SQLException cleanup) { failure.addSuppressed(cleanup); }
                throw failure;
            }
        }
    }

    private static WorkflowOperation operation(String authority) {
        for (WorkflowOperation operation : WorkflowOperation.values()) {
            if (operation.requiredAuthority().value().equals(authority)) return operation;
        }
        throw new IllegalStateException("Unknown ACL operation");
    }

    /** SQLExceptions stay unchecked inside the callback; the guarded transaction sanitizes and rolls back. */
    private static <T> T sql(SqlCall<T> call) {
        try {
            return call.run();
        } catch (SQLException failure) {
            throw new IllegalStateException("Authorized Workflow store failure", failure);
        }
    }

    @FunctionalInterface
    private interface SqlCall<T> {
        T run() throws SQLException;
    }
}
