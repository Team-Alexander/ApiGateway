package com.uptalent.gateway.jwt;

import com.uptalent.gateway.converter.PublicKeyConverter;
import com.uptalent.gateway.model.PublicKeyDTO;
import io.micrometer.common.util.StringUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static com.uptalent.gateway.jwt.JwtConstants.USER_ID_KEY;
import static com.uptalent.gateway.jwt.JwtConstants.USER_ROLE_KEY;

@Service
@Slf4j
@RequiredArgsConstructor
public class JwtService {
    private final WebClient.Builder webClientBuilder;
    private JwtDecoder jwtDecoder;
    private final ConcurrentHashMap<String, PublicKey> jtiMap = new ConcurrentHashMap<>();
    @Value("${auth-service.public-key-url}")
    private String publicKeyUrl;

    public Mono<Map<String, String>> validateTokenAndExtractUserInfo(String token) {
        return getPublicKey(token)
                .flatMap(publicKey -> decodeJwtExtractUserInfo(token))
                .defaultIfEmpty(Collections.emptyMap());
    }

    private Mono<Map<String, String>> decodeJwtExtractUserInfo(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            if (StringUtils.isNotBlank(jwt.getSubject()) && !isTokenExpired(jwt)) {
                Map<String, String> userMap = Map.of(
                        USER_ID_KEY, jwt.getSubject(),
                        USER_ROLE_KEY, jwt.getClaimAsString("role")
                );
                return Mono.just(userMap);
            }

            return Mono.empty();
        } catch (BadJwtException ex) {
            return Mono.empty();
        }
    }

    private Mono<PublicKey> getPublicKey(String token) {
        PublicKey cachedPublicKey = jtiMap.get(getJwtId(token));
        if (cachedPublicKey != null) {
            return Mono.just(cachedPublicKey);
        } else {
            return fetchPublicKey()
                    .flatMap(publicKeyDTO -> {
                        try {
                            PublicKey publicKey = PublicKeyConverter.convertToPublicKey(publicKeyDTO);
                            configureJwtDecoderWithPublicKey(publicKey);
                            jtiMap.put(getJwtId(token), publicKey);
                            return Mono.just(publicKey);
                        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
                            log.error("Convert to public key failed: ", ex);
                            return Mono.empty();
                        }
                    });
        }
    }

    private boolean isTokenExpired(Jwt jwt) {
        Instant jwtExpiresAt = jwt.getExpiresAt();
        return jwtExpiresAt == null || Instant.now().isAfter(jwtExpiresAt);
    }

    private void configureJwtDecoderWithPublicKey(PublicKey publicKey) {
        this.jwtDecoder = NimbusJwtDecoder.withPublicKey((RSAPublicKey) publicKey).build();
    }

    private Mono<PublicKeyDTO> fetchPublicKey() {
        return webClientBuilder.build()
                .get()
                .uri(publicKeyUrl)
                .retrieve()
                .bodyToMono(PublicKeyDTO.class);
    }

    private String getJwtId(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            return jwt.getId();
        } catch (NullPointerException | BadJwtException ex) {
            return "";
        }
    }

    @Scheduled(cron = "0 0 0 * * MON")
    private void clearJtiMap() {
        log.info("Clearing jti map");
        jtiMap.clear();
    }
}
