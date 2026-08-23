package com.vkonatala.auditlog;

import com.vkonatala.auditlog.application.retention.AuditRetentionProperties;
import com.vkonatala.auditlog.application.export.AuditExportSignatureProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@EnableConfigurationProperties({AuditRetentionProperties.class, AuditExportSignatureProperties.class})
public class AuditLogServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuditLogServiceApplication.class, args);
    }
}
