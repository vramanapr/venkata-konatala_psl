package com.vkonatala.auditlog.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.http.HttpStatus;

import java.util.ArrayList;
import java.util.List;

@Configuration
public class AuditSecurityConfiguration {

    @Bean
    SecurityFilterChain auditSecurityFilterChain(
            HttpSecurity http,
            @Value("${audit.security.enabled:true}") boolean enabled) throws Exception {
        http.csrf(csrf -> csrf.disable());
        if (!enabled) {
            http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
            return http.build();
        }
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                .requestMatchers("/actuator/**")
                    .hasAnyAuthority("audit:admin", "ROLE_AUDIT_ADMIN")
                .requestMatchers(org.springframework.http.HttpMethod.POST, "/api/v1/audit/events")
                    .hasAnyAuthority("audit:write", "ROLE_AUDIT_WRITE",
                            "audit:admin", "ROLE_AUDIT_ADMIN")
                .requestMatchers(org.springframework.http.HttpMethod.GET, "/api/v1/audit/events")
                    .hasAnyAuthority("audit:read", "ROLE_AUDIT_READ",
                            "audit:admin", "ROLE_AUDIT_ADMIN")
                .requestMatchers("/api/v1/audit/verify")
                    .hasAnyAuthority("audit:verify", "ROLE_AUDIT_VERIFY",
                            "audit:admin", "ROLE_AUDIT_ADMIN")
                .requestMatchers("/api/v1/audit/exports")
                    .hasAnyAuthority("audit:export", "ROLE_AUDIT_EXPORT",
                            "audit:admin", "ROLE_AUDIT_ADMIN")
                .requestMatchers(org.springframework.http.HttpMethod.POST, "/api/v1/audit/events/*/redactions")
                    .hasAnyAuthority("audit:redact", "ROLE_AUDIT_REDACT",
                            "audit:admin", "ROLE_AUDIT_ADMIN")
                .anyRequest().denyAll());
        http.exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(
                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));
        http.httpBasic(basic -> {});
        return http.build();
    }

    @Bean
    InMemoryUserDetailsManager auditUsers(
            @Value("${audit.security.users:}") String configuredUsers,
            PasswordEncoder passwordEncoder) {
        List<UserDetails> users = new ArrayList<>();
        if (configuredUsers != null && !configuredUsers.isBlank()) {
            for (String definition : configuredUsers.split("\\s*,\\s*")) {
                String[] credentials = definition.split("=", 2);
                if (credentials.length != 2) {
                    credentials = definition.split(":", 2);
                }
                if (credentials.length != 2 || credentials[0].isBlank()) {
                    throw new IllegalStateException(
                            "AUDIT_SECURITY_USERS must use username=password|scope1+scope2");
                }
                String[] passwordAndScopes = credentials[1].split("\\|", 2);
                if (passwordAndScopes.length != 2) {
                    passwordAndScopes = credentials[1].split(":", 2);
                }
                if (passwordAndScopes.length != 2 || passwordAndScopes[0].isBlank()) {
                    throw new IllegalStateException(
                            "AUDIT_SECURITY_USERS must include a password and scopes");
                }
                String[] scopes = passwordAndScopes[1].split("[+\\s]+");
                List<String> authorities = new ArrayList<>();
                for (String scope : scopes) {
                    if (!scope.isBlank()) authorities.add(normalizeScope(scope));
                }
                users.add(User.withUsername(credentials[0])
                        .password(encodeConfiguredPassword(passwordAndScopes[0]))
                        .authorities(authorities.toArray(String[]::new))
                        .build());
            }
        }
        return new InMemoryUserDetailsManager(users);
    }

    @Bean
    PasswordEncoder auditPasswordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    private String normalizeScope(String scope) {
        String normalized = scope.toLowerCase(java.util.Locale.ROOT);
        if (normalized.startsWith("role_")) normalized = normalized.substring(5);
        if ("admin".equals(normalized)) return "audit:admin";
        if (List.of("write", "read", "verify", "export", "redact").contains(normalized)) {
            return "audit:" + normalized;
        }
        if (normalized.startsWith("audit_")) {
            normalized = "audit:" + normalized.substring("audit_".length());
        }
        return normalized;
    }

    private String encodeConfiguredPassword(String password) {
        return password.startsWith("{") ? password : "{noop}" + password;
    }
}
