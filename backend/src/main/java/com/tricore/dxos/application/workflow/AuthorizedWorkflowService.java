// SPDX-FileCopyrightText: 2026 TRICORE contributors
//
// SPDX-License-Identifier: Apache-2.0

package com.tricore.dxos.application.workflow;

import com.tricore.dxos.application.authorization.TenantResourceWorkflowAccessPolicy;
import com.tricore.dxos.application.authorization.WorkflowAccessDecision;
import com.tricore.dxos.application.authorization.WorkflowAccessException;
import com.tricore.dxos.application.authorization.WorkflowAclSnapshotReader.ResourceAclSnapshot;
import com.tricore.dxos.application.authorization.WorkflowAuthorization;
import com.tricore.dxos.application.authorization.WorkflowOperation;
import com.tricore.dxos.application.identity.CurrentPrincipal;
import com.tricore.dxos.core.identity.AuthenticatedPrincipal;
import com.tricore.dxos.core.workflow.ActorReference;
import com.tricore.dxos.core.workflow.TransitionCommand;
import com.tricore.dxos.core.workflow.TransitionRecord;
import com.tricore.dxos.core.workflow.TransitionResult;
import com.tricore.dxos.core.workflow.WorkflowErrorCode;
import com.tricore.dxos.core.workflow.WorkflowException;
import com.tricore.dxos.core.workflow.WorkflowInstance;
import com.tricore.dxos.core.workflow.WorkflowRuntime;

import java.time.Clock;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Supplier;

/**
 * Application-neutral authorization boundary in front of {@link WorkflowRuntime}.
 *
 * <p>Actor and authorities come only from {@link CurrentPrincipal#requireVerified()}. A requested
 * tenant is a selection among the caller's authoritative active memberships, never proof. Inside
 * one store transaction: resolve tenant, lock it, load the instance, read ONE ACL snapshot for the
 * instance's authoritative resource, authorize the operation plus READ (results disclose state),
 * then delegate to WorkflowRuntime bound to the same transaction. Missing and cross-tenant
 * instances are both HIDDEN. Workflow errors, including COMMIT_OUTCOME_UNKNOWN, propagate unchanged.
 *
 * <p>Framework-free. Not wired as a bean or exposed over HTTP; no production {@link AuthorizedWorkflowStore}
 * adapter exists, and the policy tables such an adapter needs are unapproved candidates. Creation is
 * out of scope because it also registers the resource and its initial ACL.
 */
public final class AuthorizedWorkflowService {
    private final CurrentPrincipal currentPrincipal;
    private final AuthorizedWorkflowStore store;
    private final Clock clock;

    public AuthorizedWorkflowService(CurrentPrincipal currentPrincipal, AuthorizedWorkflowStore store, Clock clock) {
        this.currentPrincipal = Objects.requireNonNull(currentPrincipal, "currentPrincipal");
        this.store = Objects.requireNonNull(store, "store");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** @param requestedTenantId optional selection; null resolves only when exactly one membership is active */
    public WorkflowInstance get(String requestedTenantId, String instanceId) {
        return authorized(requestedTenantId, instanceId, WorkflowOperation.READ,
                (runtime, actor) -> runtime.loadInstance(instanceId));
    }

    public List<TransitionRecord> history(String requestedTenantId, String instanceId) {
        return authorized(requestedTenantId, instanceId, WorkflowOperation.READ,
                (runtime, actor) -> runtime.loadHistory(instanceId));
    }

    public WorkflowInstance activate(String requestedTenantId, String instanceId) {
        return authorized(requestedTenantId, instanceId, WorkflowOperation.ACTIVATE,
                (runtime, actor) -> runtime.activateInstance(instanceId));
    }

    public TransitionResult transition(String requestedTenantId, String instanceId, String transitionId,
                                       long expectedVersion) {
        return authorized(requestedTenantId, instanceId, WorkflowOperation.TRANSITION,
                (runtime, actor) -> runtime.executeTransition(new TransitionCommand(
                        instanceId, transitionId, new ActorReference(actor.subjectId()), expectedVersion)));
    }

    private <T> T authorized(String requestedTenantId, String instanceId, WorkflowOperation operation,
                             BiFunction<WorkflowRuntime, AuthenticatedPrincipal, T> action) {
        AuthenticatedPrincipal actor = currentPrincipal.requireVerified();
        boolean write = operation != WorkflowOperation.READ;
        return store.inTransaction(write, session -> {
            String tenant = resolveTenant(
                    authorizationFact(() -> session.activeTenantIds(actor.subjectId())), requestedTenantId);
            if (!authorizationFact(() -> session.lockTenant(tenant, write))) {
                throw denied(WorkflowAccessDecision.HIDDEN);
            }
            WorkflowRuntime runtime = new WorkflowRuntime(session.workflow(), clock);
            WorkflowInstance instance;
            try {
                instance = runtime.loadInstance(instanceId);
            } catch (WorkflowException failure) {
                // Same outcome as a cross-tenant instance: no existence oracle.
                if (failure.code() == WorkflowErrorCode.INSTANCE_NOT_FOUND) throw denied(WorkflowAccessDecision.HIDDEN);
                throw failure;
            }
            Optional<ResourceAclSnapshot> facts = aclFacts(session, instance, actor, tenant);
            var authorization = new WorkflowAuthorization(
                    new TenantResourceWorkflowAccessPolicy((resource, verifiedActor) -> facts));
            authorization.authorizeInstance(actor, instance, operation);
            authorization.authorizeInstance(actor, instance, WorkflowOperation.READ);
            return action.apply(runtime, actor);
        });
    }

    private static String resolveTenant(Set<String> activeTenants, String requestedTenantId) {
        if (activeTenants == null) throw denied(WorkflowAccessDecision.UNAVAILABLE);
        if (requestedTenantId != null) {
            if (!activeTenants.contains(requestedTenantId)) throw denied(WorkflowAccessDecision.HIDDEN);
            return requestedTenantId;
        }
        if (activeTenants.isEmpty()) throw denied(WorkflowAccessDecision.HIDDEN);
        if (activeTenants.size() > 1) throw new TenantSelectionRequiredException();
        return activeTenants.iterator().next();
    }

    /** One snapshot per operation; a snapshot from another tenant is treated as missing (HIDDEN). */
    private static Optional<ResourceAclSnapshot> aclFacts(AuthorizedWorkflowStore.Session session,
            WorkflowInstance instance, AuthenticatedPrincipal actor, String tenant) {
        return authorizationFact(() -> Objects.requireNonNull(
                session.read(instance.resourceReference(), actor.subjectId()))
                .filter(snapshot -> snapshot.tenantId().equals(tenant)));
    }

    /** Membership, tenant-lock and ACL lookup failures are UNAVAILABLE; provider details never escape. */
    private static <T> T authorizationFact(Supplier<T> lookup) {
        try {
            return lookup.get();
        } catch (RuntimeException unavailable) {
            throw denied(WorkflowAccessDecision.UNAVAILABLE);
        }
    }

    private static WorkflowAccessException denied(WorkflowAccessDecision decision) {
        return new WorkflowAccessException(decision);
    }
}
