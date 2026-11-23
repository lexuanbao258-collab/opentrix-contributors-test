// SPDX-FileCopyrightText: 2026 TRICORE contributors
//
// SPDX-License-Identifier: Apache-2.0

package com.tricore.dxos.application.workflow;

/** The verified caller has several active tenant memberships and selected none; lists no tenants. */
public final class TenantSelectionRequiredException extends RuntimeException {
    public TenantSelectionRequiredException() {
        super("Tenant selection required", null, false, false);
    }
}
