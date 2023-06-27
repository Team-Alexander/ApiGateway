package com.uptalent.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .authorizeExchange(exchanges ->
                        exchanges.anyExchange().permitAll()
                )
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(corsSpec -> corsSpec.configurationSource(request -> {
                    CorsConfiguration corsConfiguration = new CorsConfiguration().applyPermitDefaultValues();
                    corsConfiguration.addAllowedMethod(HttpMethod.PATCH);
                    corsConfiguration.addAllowedMethod(HttpMethod.PUT);
                    corsConfiguration.addAllowedMethod(HttpMethod.DELETE);
                    return corsConfiguration;
                }))
                .build();
    }
}

