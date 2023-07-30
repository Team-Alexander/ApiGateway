package io.github.uptalent.gateway.jwt;

public final class JwtConstants {
    private JwtConstants(){}

    public static final String BEARER_PREFIX = "Bearer ";
    public static final String USER_ID_KEY = "User-Id";
    public static final String USER_ROLE_KEY = "User-Role";
    public static final int EXPIRED_TIME_DAYS = 7;
    public static final int MAX_CACHE_SIZE = 10;
}
