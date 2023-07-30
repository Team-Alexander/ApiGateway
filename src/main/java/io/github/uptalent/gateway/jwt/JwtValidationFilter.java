package io.github.uptalent.gateway.jwt;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpHeaders;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

@Component
@Slf4j
@RequiredArgsConstructor
@Order(Ordered.HIGHEST_PRECEDENCE)
public class JwtValidationFilter implements GlobalFilter {
    private final JwtService jwtService;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String authorizationHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authorizationHeader != null && authorizationHeader.startsWith(JwtConstants.BEARER_PREFIX)) {
            String token = authorizationHeader.substring(JwtConstants.BEARER_PREFIX.length());

            return jwtService.validateTokenAndExtractUserInfo(token)
                    .flatMap(userInfo -> updateRequestAndChainFilter(exchange, chain, userInfo))
                    .switchIfEmpty(chain.filter(exchange));
        }

        return chain.filter(exchange);
    }

    private Mono<Void> updateRequestAndChainFilter(ServerWebExchange exchange, GatewayFilterChain chain, Map<String, String> userInfo) {
        ServerHttpRequest updatedRequest = exchange.getRequest().mutate()
                .headers(headers -> {
                    headers.set(JwtConstants.USER_ID_KEY, userInfo.get(JwtConstants.USER_ID_KEY));
                    headers.set(JwtConstants.USER_ROLE_KEY, userInfo.get(JwtConstants.USER_ROLE_KEY));
                })
                .build();

        return chain.filter(exchange.mutate().request(updatedRequest).build());
    }
}