package io.github.uptalent.gateway.jwt;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import io.github.uptalent.gateway.converter.PublicKeyConverter;
import io.github.uptalent.gateway.exception.BlockedAccountException;
import io.github.uptalent.gateway.exception.InvalidTokenException;
import io.github.uptalent.gateway.model.PublicKeyDTO;
import io.micrometer.common.util.StringUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
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
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static io.github.uptalent.gateway.jwt.JwtConstants.*;

@Service
@Slf4j
@RequiredArgsConstructor
public class JwtService {
    private JwtDecoder jwtDecoder;
    @Value("${auth-service.public-key-url}")
    private String publicKeyUrl;
    private final WebClient.Builder webClientBuilder;
    private final RedisTemplate<String, String> redisTemplate;
    private final Cache<String, PublicKey> jtiMap = CacheBuilder.newBuilder()
            .expireAfterWrite(EXPIRED_TIME_DAYS, TimeUnit.DAYS)
            .maximumSize(MAX_CACHE_SIZE)
            .build();
    private static final String JWT_BLACKLIST = "jwt_blacklist:";
    private static final String BLOCKED_ACCOUNT = "blocked_account:";

    public Mono<Map<String, String>> validateTokenAndExtractUserInfo(String token) {
        String key = JWT_BLACKLIST + token.toLowerCase();
        boolean isBlacklisted = Boolean.TRUE.equals(redisTemplate.hasKey(key));
        if(isBlacklisted)
            throw new InvalidTokenException();

        return getPublicKey(token)
                .flatMap(publicKey -> {
                    try {
                        if (publicKey != null) {
                            Jwt jwt = jwtDecoder.decode(token);
                            if (StringUtils.isNotEmpty(jwt.getSubject()) && !isTokenExpired(jwt)) {
                                validateBlockedAccount(jwt);
                                return Mono.just(extractUserInfo(jwt));
                            }
                        }
                    } catch (BadJwtException ex) {
                        return Mono.error(new InvalidTokenException());
                    }
                    return Mono.error(new InvalidTokenException());
                });
    }

    private void validateBlockedAccount(Jwt jwt) {
        String email = jwt.getClaimAsString("email");
        if(Boolean.TRUE.equals(redisTemplate.hasKey(BLOCKED_ACCOUNT + email)))
            throw new BlockedAccountException();
    }

    private Map<String, String> extractUserInfo(Jwt jwt) {
        return Map.of(
                USER_ID_KEY, jwt.getSubject(),
                USER_ROLE_KEY, jwt.getClaimAsString("role")
        );
    }

    private Mono<PublicKey> getPublicKey(String token) {
        PublicKey cachedPublicKey = jtiMap.asMap().get(getJwtId(token));
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
}
