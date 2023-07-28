package io.github.uptalent.gateway.exception;

public final class ExceptionConstant {
    private ExceptionConstant(){}

    public static final String NOT_FOUND_MESSAGE = "Resource is not found, please try again later";
    public static final String SERVICE_UNAVAILABLE_MESSAGE = "Service is unavailable, please try again later";
    public static final String INTERNAL_SERVER_ERROR_MESSAGE = "A server error occurred";
    public static final String INVALID_TOKEN_MESSAGE = "Invalid jwt token";
}
