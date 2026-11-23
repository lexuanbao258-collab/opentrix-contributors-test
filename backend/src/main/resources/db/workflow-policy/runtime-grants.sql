-- SPDX-FileCopyrightText: 2026 TRICORE contributors
--
-- SPDX-License-Identifier: Apache-2.0

-- Minimum privileges for the generic authorized Workflow runtime (PostgresAuthorizedWorkflowStore).
-- CANDIDATE / NOT PRODUCTION-APPROVED. Apply after V5 with validated identifiers replacing both placeholders; not a Flyway
-- migration because roles are environment-specific and the guarded Flyway configuration rejects
-- custom placeholders. The runtime role must be LOGIN, NOSUPERUSER, NOBYPASSRLS and own nothing.
--
-- Deliberately absent: any policy write (memberships, registry, ACL, bindings), definition writes,
-- workflow_instances INSERT/DELETE, history UPDATE/DELETE, TRUNCATE, schema CREATE.
-- Creating instances (registry + ACL + instance) is a later use case with its own grants.
--
-- Idempotent and convergent: applied by the NOSUPERUSER schema owner, it first removes every privilege the runtime
-- holds in the schema (legacy or hand-added), so re-running it restores exactly the set below.
DO $converge$
BEGIN
    PERFORM pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true);
    IF (SELECT pg_catalog.pg_get_userbyid(n.nspowner) FROM pg_catalog.pg_namespace n
            WHERE n.nspname = '${flyway:defaultSchema}') IS DISTINCT FROM current_user
            OR EXISTS (SELECT FROM pg_catalog.pg_roles r WHERE r.rolname = current_user
                    AND (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication)) THEN
        RAISE EXCEPTION 'runtime grants must be applied by the NOSUPERUSER schema owner' USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname = '${workflow:runtimeRole}' AND r.rolcanlogin
                AND NOT (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication))
            OR '${workflow:runtimeRole}' = current_user
            OR '${workflow:runtimeRole}' !~ '^(wfpol|workflow)_runtime_[a-z0-9_]+$'
            OR pg_catalog.has_database_privilege('${workflow:runtimeRole}', pg_catalog.current_database(), 'CREATE')
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
                       WHERE m.member = '${workflow:runtimeRole}'::regrole OR m.roleid = '${workflow:runtimeRole}'::regrole)
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_class c WHERE c.relowner = '${workflow:runtimeRole}'::regrole)
            OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc p WHERE p.proowner = '${workflow:runtimeRole}'::regrole) THEN
        RAISE EXCEPTION 'runtime must be an unprivileged LOGIN that owns nothing and belongs to no role'
            USING ERRCODE = '42501';
    END IF;
    REVOKE ALL ON ALL TABLES IN SCHEMA "${flyway:defaultSchema}" FROM "${workflow:runtimeRole}";
    REVOKE ALL ON ALL SEQUENCES IN SCHEMA "${flyway:defaultSchema}" FROM "${workflow:runtimeRole}";
    REVOKE ALL ON ALL FUNCTIONS IN SCHEMA "${flyway:defaultSchema}" FROM "${workflow:runtimeRole}";
    REVOKE CREATE ON SCHEMA "${flyway:defaultSchema}" FROM "${workflow:runtimeRole}";
    IF pg_catalog.has_schema_privilege('${workflow:runtimeRole}', '"${flyway:defaultSchema}"'::regnamespace::oid, 'CREATE')
        OR EXISTS (
            SELECT FROM pg_catalog.pg_class c
            WHERE c.relnamespace = '"${flyway:defaultSchema}"'::regnamespace AND c.relkind IN ('r','p','v','m','f')
                AND (pg_catalog.has_table_privilege('${workflow:runtimeRole}', c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
                    OR pg_catalog.has_any_column_privilege('${workflow:runtimeRole}', c.oid, 'SELECT,INSERT,UPDATE,REFERENCES'))
        )
        OR EXISTS (
            SELECT FROM pg_catalog.pg_proc p WHERE p.pronamespace = '"${flyway:defaultSchema}"'::regnamespace
                AND pg_catalog.has_function_privilege('${workflow:runtimeRole}', p.oid, 'EXECUTE')
        ) THEN
        RAISE EXCEPTION 'Workflow runtime retains effective privileges after revoke' USING ERRCODE = '42501';
    END IF;

    GRANT USAGE ON SCHEMA "${flyway:defaultSchema}" TO "${workflow:runtimeRole}";

    GRANT SELECT ON
        "${flyway:defaultSchema}".tenant_guards,
        "${flyway:defaultSchema}".tenant_memberships,
        "${flyway:defaultSchema}".resource_registry,
        "${flyway:defaultSchema}".resource_acl,
        "${flyway:defaultSchema}".workflow_definition_bindings,
        "${flyway:defaultSchema}".workflow_definitions,
        "${flyway:defaultSchema}".workflow_definition_states,
        "${flyway:defaultSchema}".workflow_definition_transitions,
        "${flyway:defaultSchema}".workflow_instances,
        "${flyway:defaultSchema}".workflow_transition_history
    TO "${workflow:runtimeRole}";

    -- PostgreSQL requires UPDATE on at least one column for SELECT ... FOR SHARE/FOR UPDATE.
    -- acl_revision can only grow (identity guard); the runtime never writes it.
    GRANT UPDATE (acl_revision) ON "${flyway:defaultSchema}".tenant_guards TO "${workflow:runtimeRole}";

    -- Activation and transition commits (instance row lock, compare-and-set) plus one history row.
    GRANT UPDATE (current_state, runtime_version, lifecycle, updated_at_seconds, updated_at_nanos)
        ON "${flyway:defaultSchema}".workflow_instances TO "${workflow:runtimeRole}";
    GRANT INSERT ON "${flyway:defaultSchema}".workflow_transition_history TO "${workflow:runtimeRole}";
END;
$converge$;
