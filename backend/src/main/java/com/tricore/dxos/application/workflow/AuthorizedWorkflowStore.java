// SPDX-FileCopyrightText: 2026 TRICORE contributors
//
// SPDX-License-Identifier: Apache-2.0

package com.tricore.dxos.application.workflow;

import com.tricore.dxos.application.authorization.WorkflowAclSnapshotReader;
import com.tricore.dxos.core.workflow.WorkflowPersistencePort;

import java.util.Set;
import java.util.function.Function;

/**
 * Driven port: ONE authoritative transaction per authorized Workflow operation, so tenant
 * membership, ACL facts and the Workflow write are read and committed together.
 *
 * <p>No production adapter exists yet. A PostgreSQL adapter must reuse the guarded transaction
 * semantics of the Workflow persistence adapter: commit only after the callback returns normally;
 * roll back on any exception and rethrow {@code WorkflowException}/{@code WorkflowAccessException}
 * unchanged; translate a failure after COMMIT was attempted to {@code COMMIT_OUTCOME_UNKNOWN};
 * translate other provider failures to sanitized UNAVAILABLE/OPERATION_FAILURE; never retry.
 */
public interface AuthorizedWorkflowStore {
    <T> T inTransaction(boolean write, Function<Session, T> work);

    /**
     * Valid only inside {@link #inTransaction}. Every method participates in that transaction;
     * none commits. ACL snapshots ({@link #read}) must report the resource's authoritative tenant.
     */
    interface Session extends WorkflowAclSnapshotReader {
        /** Tenants where the verified canonical actor has an ACTIVE membership; never from request input. */
        Set<String> activeTenantIds(String verifiedActorId);

        /**
         * Takes the tenant guard lock that policy edits also take (shared for reads, exclusive for
         * writes) and returns false when the tenant guard does not exist. Facts read afterwards
         * must reflect any revocation that committed while waiting.
         */
        boolean lockTenant(String tenantId, boolean exclusive);

        /** Workflow persistence bound to this transaction; its writes commit only with the owner. */
        WorkflowPersistencePort workflow();
    }
}
