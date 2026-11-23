// SPDX-FileCopyrightText: 2026 TRICORE contributors
//
// SPDX-License-Identifier: Apache-2.0

package com.tricore.dxos.infrastructure.workflow;

import org.flywaydb.core.Flyway;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;
import java.util.UUID;

/**
 * Disposable schema on the loopback Helpdesk test database, migrated by real Flyway as a dedicated
 * NOSUPERUSER migrator that owns the schema. The runtime role receives only
 * db/workflow-policy/runtime-grants.sql. Test harness only: production migrations must run through
 * WorkflowMigrations, whose reviewed manifest excludes the V5–V6 candidates.
 */
final class WorkflowPolicyFixture implements AutoCloseable {
    static final String MIGRATIONS = "classpath:db/migration";
    static final String POLICY_CANDIDATE = "classpath:db/workflow-policy";

    final String url = System.getenv("HELPDESK_DISPOSABLE_URL");
    final String schema;
    final String migratorRole;
    final String runtimeRole;
    private final String migratorPassword = UUID.randomUUID().toString();
    private final String runtimePassword = UUID.randomUUID().toString();

    WorkflowPolicyFixture() throws SQLException {
        if (!"jdbc:postgresql://127.0.0.1:55439/helpdesk_disposable_test".equals(url)
                || !"true".equals(System.getenv("WORKFLOW_EVENT_GUARD_LOCAL_DISPOSABLE"))) {
            throw new IllegalStateException("An explicitly disposable loopback PostgreSQL fixture is required");
        }
        String suffix = UUID.randomUUID().toString().replace("-", "");
        schema = "wfpol_" + suffix;
        migratorRole = "wfpol_migrator_" + suffix;
        runtimeRole = "wfpol_runtime_" + suffix;
        try (var c = admin()) {
            try (var s = c.createStatement(); var r = s.executeQuery(
                    "SELECT current_setting('server_version_num')::int BETWEEN 170000 AND 179999")) {
                if (!r.next() || !r.getBoolean(1)) throw new IllegalStateException("Expected PostgreSQL 17");
            }
            sql(c, "CREATE ROLE " + migratorRole + " LOGIN PASSWORD '" + migratorPassword
                    + "' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT");
            sql(c, "CREATE ROLE " + runtimeRole + " LOGIN PASSWORD '" + runtimePassword
                    + "' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT");
            sql(c, "CREATE SCHEMA " + schema + " AUTHORIZATION " + migratorRole);
            sql(c, "REVOKE ALL ON SCHEMA " + schema + " FROM PUBLIC");
        }
    }

    Flyway flyway(String... locations) {
        return flywayAt("latest", locations);
    }

    Flyway flywayAt(String target, String... locations) {
        return Flyway.configure().dataSource(url, migratorRole, migratorPassword).locations(locations)
                .defaultSchema(schema).schemas(schema).createSchemas(false).cleanDisabled(true)
                .baselineOnMigrate(false).outOfOrder(false).ignoreMigrationPatterns(new String[0]).target(target).load();
    }

    /** Operator step: the schema owner applies the generic runtime grants with validated identifiers. */
    void grantRuntime() throws Exception {
        String grants = Files.readString(Path.of("src/main/resources/db/workflow-policy/runtime-grants.sql"))
                .replace("${flyway:defaultSchema}", schema).replace("${workflow:runtimeRole}", runtimeRole);
        try (var c = migrator()) {
            sql(c, grants);
        }
    }

    DataSource runtimeDataSource() {
        return dataSource(runtimeRole, runtimePassword);
    }

    DataSource migratorDataSource() {
        return dataSource(migratorRole, migratorPassword);
    }

    Connection migrator() throws SQLException {
        return migratorDataSource().getConnection();
    }

    Connection runtime() throws SQLException {
        return runtimeDataSource().getConnection();
    }

    Connection admin() throws SQLException {
        String secret = System.getenv("HELPDESK_DISPOSABLE_PASSWORD");
        return DriverManager.getConnection(url, "helpdesk_test", secret == null ? "" : secret);
    }

    private DataSource dataSource(String user, String password) {
        var source = new DriverManagerDataSource(url, user, password);
        var properties = new Properties();
        properties.setProperty("currentSchema", schema + ",pg_catalog,pg_temp");
        source.setConnectionProperties(properties);
        return source;
    }

    static void sql(Connection c, String sql) throws SQLException {
        try (var s = c.createStatement()) {
            s.execute(sql);
        }
    }

    @Override
    public void close() throws SQLException {
        if (!schema.matches("wfpol_[a-f0-9]{32}")) throw new IllegalStateException("unexpected fixture schema");
        try (var c = admin()) {
            sql(c, "DROP SCHEMA IF EXISTS " + schema + " CASCADE");
            sql(c, "DROP ROLE IF EXISTS " + runtimeRole);
            sql(c, "DROP ROLE IF EXISTS " + migratorRole);
        }
    }
}
