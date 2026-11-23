-- SPDX-FileCopyrightText: 2026 TRICORE contributors
--
-- SPDX-License-Identifier: Apache-2.0

-- Generic Workflow tenant/resource policy for AuthorizedWorkflowService.
-- CANDIDATE / NOT PRODUCTION-APPROVED. Intentionally outside classpath:db/migration.
--
-- PostgreSQL 17. Run with validated Flyway V1-V4 history and all old writers stopped.
-- Adopt only the reviewed Helpdesk catalog shape, in place, without modifying rows or legacy ACLs.
--
-- Isolation model: shared schema, tenant derived from resource_registry by the authoritative
-- (resource_type, resource_id) key. Tenant identity of a resource is immutable.
-- Locking protocol: every policy edit locks its tenant_guards row FOR UPDATE (trigger below);
-- authorized Workflow reads lock it FOR SHARE and writes FOR UPDATE before reading ACL facts.

SET LOCAL search_path = pg_catalog, pg_temp;
SET LOCAL lock_timeout = '5s';

DO $policy$
DECLARE
    schema_id oid := '"${flyway:defaultSchema}"'::regnamespace;
    policy_names text[] := ARRAY['tenant_guards', 'tenant_memberships', 'resource_registry',
        'resource_acl', 'workflow_definition_bindings', 'workflow_policy_audit'];
    present integer;
    fingerprint text;
BEGIN
    IF current_setting('server_version_num')::int NOT BETWEEN 170000 AND 179999
        OR EXISTS (SELECT FROM pg_event_trigger WHERE evtenabled <> 'D')
        OR NOT EXISTS (
            SELECT FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner
            WHERE n.oid = schema_id AND r.rolname = current_user
                AND NOT (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls)
                AND NOT EXISTS (SELECT FROM aclexplode(n.nspacl) a WHERE a.grantee = 0)
        ) THEN
        RAISE EXCEPTION 'Workflow Policy V5 requires PostgreSQL 17, no active event triggers and a sealed schema owned by the unprivileged migrator';
    END IF;

    SELECT count(*) INTO present FROM pg_class WHERE relnamespace = schema_id AND relname = ANY(policy_names);
    IF present = 0 AND NOT EXISTS (
            SELECT FROM pg_proc WHERE pronamespace = schema_id
            AND proname IN ('stage6_policy_immutability_guard', 'helpdesk_policy_lock')
        ) AND NOT EXISTS (
            SELECT FROM pg_class WHERE relnamespace = schema_id AND relname IN ('helpdesk_actors', 'helpdesk_requests')
        ) THEN
        CREATE TABLE "${flyway:defaultSchema}".tenant_guards (
            tenant_id TEXT PRIMARY KEY CHECK (length(btrim(tenant_id)) > 0),
            acl_revision BIGINT NOT NULL DEFAULT 0 CHECK (acl_revision >= 0)
        );

        CREATE TABLE "${flyway:defaultSchema}".tenant_memberships (
            tenant_id TEXT NOT NULL REFERENCES "${flyway:defaultSchema}".tenant_guards(tenant_id)
                ON UPDATE RESTRICT ON DELETE RESTRICT,
            actor_id TEXT NOT NULL CHECK (length(btrim(actor_id)) > 0),
            active BOOLEAN NOT NULL,
            PRIMARY KEY (tenant_id, actor_id)
        );

        CREATE TABLE "${flyway:defaultSchema}".resource_registry (
            resource_type TEXT NOT NULL CHECK (length(btrim(resource_type)) > 0),
            resource_id TEXT NOT NULL CHECK (length(btrim(resource_id)) > 0),
            tenant_id TEXT NOT NULL REFERENCES "${flyway:defaultSchema}".tenant_guards(tenant_id)
                ON UPDATE RESTRICT ON DELETE RESTRICT,
            owner_actor_id TEXT NOT NULL CHECK (length(btrim(owner_actor_id)) > 0),
            lifecycle TEXT NOT NULL CHECK (lifecycle IN ('ACTIVE', 'TOMBSTONED')),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            tombstoned_at TIMESTAMPTZ,
            -- One global resource identity: a (type, id) pair can never belong to two tenants.
            PRIMARY KEY (resource_type, resource_id),
            UNIQUE (tenant_id, resource_type, resource_id),
            FOREIGN KEY (tenant_id, owner_actor_id)
                REFERENCES "${flyway:defaultSchema}".tenant_memberships(tenant_id, actor_id)
                ON UPDATE RESTRICT ON DELETE RESTRICT,
            CHECK ((lifecycle = 'ACTIVE' AND tombstoned_at IS NULL)
                OR (lifecycle = 'TOMBSTONED' AND tombstoned_at IS NOT NULL)),
            CHECK (tombstoned_at IS NULL OR tombstoned_at >= created_at)
        );

        CREATE TABLE "${flyway:defaultSchema}".resource_acl (
            tenant_id TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            operation TEXT NOT NULL CHECK (operation IN (
                'workflow:create', 'workflow:activate', 'workflow:transition', 'workflow:read'
            )),
            granted BOOLEAN NOT NULL,
            PRIMARY KEY (tenant_id, resource_type, resource_id, actor_id, operation),
            -- Composite keys make an ACL row unable to point at another tenant's resource or member.
            FOREIGN KEY (tenant_id, resource_type, resource_id)
                REFERENCES "${flyway:defaultSchema}".resource_registry(tenant_id, resource_type, resource_id)
                ON UPDATE RESTRICT ON DELETE RESTRICT,
            FOREIGN KEY (tenant_id, actor_id)
                REFERENCES "${flyway:defaultSchema}".tenant_memberships(tenant_id, actor_id)
                ON UPDATE RESTRICT ON DELETE RESTRICT
        );

        CREATE TABLE "${flyway:defaultSchema}".workflow_definition_bindings (
            tenant_id TEXT NOT NULL REFERENCES "${flyway:defaultSchema}".tenant_guards(tenant_id)
                ON UPDATE RESTRICT ON DELETE RESTRICT,
            resource_type TEXT NOT NULL CHECK (length(btrim(resource_type)) > 0),
            definition_id TEXT NOT NULL CHECK (length(btrim(definition_id)) > 0),
            definition_version BIGINT NOT NULL CHECK (definition_version >= 0),
            active BOOLEAN NOT NULL,
            PRIMARY KEY (tenant_id, resource_type, definition_id, definition_version),
            FOREIGN KEY (definition_id, definition_version)
                REFERENCES "${flyway:defaultSchema}".workflow_definitions(definition_id, definition_version)
                ON UPDATE RESTRICT ON DELETE RESTRICT
        );
        RETURN;
    END IF;

    IF present <> cardinality(policy_names) OR EXISTS (
        SELECT FROM pg_class
        WHERE relnamespace = schema_id AND relname = ANY(policy_names)
            AND (relkind <> 'r' OR relpersistence <> 'p' OR relowner <> current_user::regrole)
    ) THEN
        RAISE EXCEPTION 'unsupported Helpdesk policy: partial objects, unexpected relation kind or ownership';
    END IF;

    LOCK TABLE "${flyway:defaultSchema}".tenant_guards, "${flyway:defaultSchema}".tenant_memberships,
        "${flyway:defaultSchema}".resource_registry, "${flyway:defaultSchema}".resource_acl,
        "${flyway:defaultSchema}".workflow_definition_bindings, "${flyway:defaultSchema}".workflow_policy_audit
        IN ACCESS EXCLUSIVE MODE;

    -- Fingerprints derive from db/helpdesk/policy-schema.sql, alone and with db/helpdesk/schema.sql.
    -- Stable catalog definitions capture schema drift without including row data, object OIDs or the schema name.
    WITH relations AS (
        SELECT * FROM pg_class WHERE relnamespace = schema_id AND relname = ANY(policy_names)
    ), triggers AS (
        SELECT t.*, r.relname FROM pg_trigger t JOIN relations r ON r.oid = t.tgrelid
        WHERE NOT t.tgisinternal
    ), routines AS (
        SELECT p.* FROM pg_proc p WHERE p.oid IN (SELECT tgfoid FROM triggers)
    ), objects AS (
        SELECT 'table' AS kind, r.relname::text AS relation, ''::text AS name,
            jsonb_build_array(r.relrowsecurity, r.relforcerowsecurity, r.relhasrules, r.relispartition,
                EXISTS (SELECT FROM pg_inherits i WHERE r.oid IN (i.inhrelid, i.inhparent)))::text AS definition
        FROM relations r
        UNION ALL
        SELECT 'column', r.relname, a.attname,
            jsonb_build_array(format_type(a.atttypid, a.atttypmod), a.attnotnull, a.attidentity, a.attgenerated,
                CASE WHEN a.attcollation <> 0 THEN a.attcollation::regcollation::text END,
                pg_get_expr(d.adbin, d.adrelid))::text
        FROM relations r JOIN pg_attribute a ON a.attrelid = r.oid
        LEFT JOIN pg_attrdef d ON d.adrelid = r.oid AND d.adnum = a.attnum
        WHERE a.attnum > 0 AND NOT a.attisdropped
        UNION ALL
        SELECT 'constraint', r.relname, c.conname, c.convalidated::text || ':' || pg_get_constraintdef(c.oid)
        FROM relations r JOIN pg_constraint c ON c.conrelid = r.oid
        UNION ALL
        SELECT 'index', r.relname, x.relname, jsonb_build_array(i.indisvalid, i.indisready, i.indislive,
            pg_get_indexdef(i.indexrelid))::text
        FROM relations r JOIN pg_index i ON i.indrelid = r.oid JOIN pg_class x ON x.oid = i.indexrelid
        UNION ALL
        SELECT 'trigger', t.relname, t.tgname, t.tgenabled::text || ':' || pg_get_triggerdef(t.oid)
        FROM triggers t
        UNION ALL
        SELECT 'routine', '', p.proname, pg_get_functiondef(p.oid) FROM routines p
    ), normalized AS (
        SELECT kind, relation, name,
            replace(replace(definition, '"${flyway:defaultSchema}".', '<schema>.'),
                quote_ident('${flyway:defaultSchema}') || '.', '<schema>.') AS definition
        FROM objects
    )
    SELECT encode(sha256(convert_to(jsonb_agg(jsonb_build_array(kind, relation, name, definition)
        ORDER BY kind COLLATE "C", relation COLLATE "C", name COLLATE "C", definition COLLATE "C")::text, 'UTF8')), 'hex')
    INTO fingerprint
    FROM normalized;

    IF fingerprint IS NULL OR fingerprint NOT IN (
            'd11676630c8deaada5a7001e58cf96a241098537a3a446a55def883123986c63',
            '3ef8c2504e2e075585b791480741385596879f32530a1113cd753b123ac755fc'
        )
        OR EXISTS (SELECT FROM pg_proc p WHERE p.pronamespace = schema_id AND p.proname LIKE 'wf\_port\_%')
        OR EXISTS (
            SELECT FROM pg_class r CROSS JOIN LATERAL aclexplode(r.relacl) a
            WHERE r.relnamespace = schema_id AND r.relname = ANY(policy_names) AND a.grantee = 0
        )
        OR EXISTS (
            SELECT FROM pg_class r JOIN pg_attribute col ON col.attrelid = r.oid
            CROSS JOIN LATERAL aclexplode(col.attacl) a
            WHERE r.relnamespace = schema_id AND r.relname = ANY(policy_names) AND a.grantee = 0
        )
        OR EXISTS (
            SELECT FROM pg_trigger t JOIN pg_class r ON r.oid = t.tgrelid
            WHERE r.relnamespace = schema_id AND r.relname = ANY(policy_names)
                AND t.tgisinternal AND t.tgenabled <> 'O'
        )
        OR EXISTS (
            SELECT FROM pg_proc p
            WHERE p.oid IN (SELECT t.tgfoid FROM pg_trigger t JOIN pg_class r ON r.oid = t.tgrelid
                           WHERE r.relnamespace = schema_id AND r.relname = ANY(policy_names) AND NOT t.tgisinternal)
                AND (p.pronamespace <> schema_id OR p.proowner <> current_user::regrole
                    OR EXISTS (SELECT FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a WHERE a.grantee = 0))
        ) THEN
        RAISE EXCEPTION 'unsupported Helpdesk policy: unexpected catalog or grants (fingerprint %)', fingerprint;
    END IF;
END;
$policy$;

-- Tenant resolution reads active memberships by actor; the primary key leads with tenant_id.
CREATE INDEX tenant_memberships_active_actor_idx
    ON "${flyway:defaultSchema}".tenant_memberships(actor_id) WHERE active;

-- Identity columns are immutable and policy rows are never deleted or truncated: moving a resource,
-- ACL row or membership to another tenant would otherwise bypass isolation. Lifecycle columns
-- (active, granted, lifecycle, acl_revision increase) remain editable by the policy owner.
CREATE FUNCTION "${flyway:defaultSchema}".workflow_policy_identity_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $guard$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'workflow policy relations cannot be truncated' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'workflow policy identities cannot be deleted' USING ERRCODE = '23514';
    END IF;
    IF TG_TABLE_NAME = 'tenant_guards' THEN
        IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.acl_revision < OLD.acl_revision THEN
            RAISE EXCEPTION 'immutable tenant key or decreasing ACL revision' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'tenant_memberships' THEN
        IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.actor_id IS DISTINCT FROM OLD.actor_id THEN
            RAISE EXCEPTION 'membership identity is immutable' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'resource_registry' THEN
        IF NEW.resource_type IS DISTINCT FROM OLD.resource_type
                OR NEW.resource_id IS DISTINCT FROM OLD.resource_id
                OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
                OR NEW.created_at IS DISTINCT FROM OLD.created_at
                OR (OLD.lifecycle = 'TOMBSTONED'
                    AND (NEW.lifecycle <> 'TOMBSTONED' OR NEW.tombstoned_at IS DISTINCT FROM OLD.tombstoned_at)) THEN
            RAISE EXCEPTION 'immutable resource key, tenant or tombstone' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'resource_acl' THEN
        IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
                OR NEW.resource_type IS DISTINCT FROM OLD.resource_type
                OR NEW.resource_id IS DISTINCT FROM OLD.resource_id
                OR NEW.actor_id IS DISTINCT FROM OLD.actor_id
                OR NEW.operation IS DISTINCT FROM OLD.operation THEN
            RAISE EXCEPTION 'ACL identity is immutable' USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'workflow_definition_bindings' THEN
        IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
                OR NEW.resource_type IS DISTINCT FROM OLD.resource_type
                OR NEW.definition_id IS DISTINCT FROM OLD.definition_id
                OR NEW.definition_version IS DISTINCT FROM OLD.definition_version THEN
            RAISE EXCEPTION 'definition binding identity is immutable' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$guard$;

-- Serializes every policy edit with authorized Workflow operations of the same tenant.
-- SECURITY INVOKER: the editor needs row-lock privilege on tenant_guards; the function grants none.
CREATE FUNCTION "${flyway:defaultSchema}".workflow_policy_tenant_lock()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $lock$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        PERFORM 1 FROM "${flyway:defaultSchema}".tenant_guards WHERE tenant_id = OLD.tenant_id FOR UPDATE;
    END IF;
    IF TG_OP <> 'DELETE' THEN
        PERFORM 1 FROM "${flyway:defaultSchema}".tenant_guards WHERE tenant_id = NEW.tenant_id FOR UPDATE;
        RETURN NEW;
    END IF;
    RETURN OLD;
END;
$lock$;

CREATE TRIGGER workflow_policy_lock BEFORE INSERT OR UPDATE OR DELETE ON "${flyway:defaultSchema}".tenant_memberships
    FOR EACH ROW EXECUTE FUNCTION "${flyway:defaultSchema}".workflow_policy_tenant_lock();
CREATE TRIGGER workflow_policy_lock BEFORE INSERT OR UPDATE OR DELETE ON "${flyway:defaultSchema}".resource_registry
    FOR EACH ROW EXECUTE FUNCTION "${flyway:defaultSchema}".workflow_policy_tenant_lock();
CREATE TRIGGER workflow_policy_lock BEFORE INSERT OR UPDATE OR DELETE ON "${flyway:defaultSchema}".resource_acl
    FOR EACH ROW EXECUTE FUNCTION "${flyway:defaultSchema}".workflow_policy_tenant_lock();
CREATE TRIGGER workflow_policy_lock BEFORE INSERT OR UPDATE OR DELETE ON "${flyway:defaultSchema}".workflow_definition_bindings
    FOR EACH ROW EXECUTE FUNCTION "${flyway:defaultSchema}".workflow_policy_tenant_lock();

CREATE TRIGGER workflow_policy_identity BEFORE UPDATE OR DELETE ON "${flyway:defaultSchema}".tenant_guards
    FOR EACH ROW EXECUTE FUNCTION "${flyway:defaultSchema}".workflow_policy_identity_guard();
CREATE TRIGGER workflow_policy_identity BEFORE UPDATE OR DELETE ON "${flyway:defaultSchema}".tenant_memberships
    FOR EACH ROW EXECUTE FUNCTION "${flyway:defaultSchema}".workflow_policy_identity_guard();
CREATE TRIGGER workflow_policy_identity BEFORE UPDATE OR DELETE ON "${flyway:defaultSchema}".resource_registry
    FOR EACH ROW EXECUTE FUNCTION "${flyway:defaultSchema}".workflow_policy_identity_guard();
CREATE TRIGGER workflow_policy_identity BEFORE UPDATE OR DELETE ON "${flyway:defaultSchema}".resource_acl
    FOR EACH ROW EXECUTE FUNCTION "${flyway:defaultSchema}".workflow_policy_identity_guard();
CREATE TRIGGER workflow_policy_identity BEFORE UPDATE OR DELETE ON "${flyway:defaultSchema}".workflow_definition_bindings
    FOR EACH ROW EXECUTE FUNCTION "${flyway:defaultSchema}".workflow_policy_identity_guard();

CREATE TRIGGER workflow_policy_no_truncate BEFORE TRUNCATE ON "${flyway:defaultSchema}".tenant_guards
    FOR EACH STATEMENT EXECUTE FUNCTION "${flyway:defaultSchema}".workflow_policy_identity_guard();
CREATE TRIGGER workflow_policy_no_truncate BEFORE TRUNCATE ON "${flyway:defaultSchema}".tenant_memberships
    FOR EACH STATEMENT EXECUTE FUNCTION "${flyway:defaultSchema}".workflow_policy_identity_guard();
CREATE TRIGGER workflow_policy_no_truncate BEFORE TRUNCATE ON "${flyway:defaultSchema}".resource_registry
    FOR EACH STATEMENT EXECUTE FUNCTION "${flyway:defaultSchema}".workflow_policy_identity_guard();
CREATE TRIGGER workflow_policy_no_truncate BEFORE TRUNCATE ON "${flyway:defaultSchema}".resource_acl
    FOR EACH STATEMENT EXECUTE FUNCTION "${flyway:defaultSchema}".workflow_policy_identity_guard();
CREATE TRIGGER workflow_policy_no_truncate BEFORE TRUNCATE ON "${flyway:defaultSchema}".workflow_definition_bindings
    FOR EACH STATEMENT EXECUTE FUNCTION "${flyway:defaultSchema}".workflow_policy_identity_guard();

REVOKE ALL ON FUNCTION "${flyway:defaultSchema}".workflow_policy_identity_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION "${flyway:defaultSchema}".workflow_policy_tenant_lock() FROM PUBLIC;
REVOKE ALL ON
    "${flyway:defaultSchema}".tenant_guards,
    "${flyway:defaultSchema}".tenant_memberships,
    "${flyway:defaultSchema}".resource_registry,
    "${flyway:defaultSchema}".resource_acl,
    "${flyway:defaultSchema}".workflow_definition_bindings
FROM PUBLIC;
