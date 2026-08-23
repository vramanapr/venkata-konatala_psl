package com.vkonatala.auditlog;

import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.flywaydb.core.Flyway;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers
class AuditSchemaIT {

    @Container
    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("auditlog")
                    .withUsername("auditlog")
                    .withPassword("auditlog");

    @Test
    void flywayCreatesAuditSchema() throws SQLException {
        Flyway.configure()
                .dataSource(
                        POSTGRES.getJdbcUrl(),
                        POSTGRES.getUsername(),
                        POSTGRES.getPassword())
                .load()
                .migrate();

        try (Connection connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(),
                POSTGRES.getUsername(),
                POSTGRES.getPassword())) {
            Set<String> tables = tableNames(connection);

            assertThat(tables).contains(
                    "audit_chain_head",
                    "audit_record",
                    "audit_record_archive",
                    "audit_idempotency",
                    "audit_redaction",
                    "audit_archive_segment");
        }
    }

    private Set<String> tableNames(Connection connection) throws SQLException {
        DatabaseMetaData metadata = connection.getMetaData();
        try (ResultSet resultSet = metadata.getTables(
                connection.getCatalog(), null, "%", new String[]{"TABLE"})) {
            return resultSetToSet(resultSet);
        }
    }

    private Set<String> resultSetToSet(ResultSet resultSet) throws SQLException {
        Set<String> names = new java.util.HashSet<>();
        while (resultSet.next()) {
            names.add(resultSet.getString("TABLE_NAME"));
        }
        return names.stream().collect(Collectors.toUnmodifiableSet());
    }
}
