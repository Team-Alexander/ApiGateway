package io.github.uptalent.gateway.exception;

public class BlockedAccountException extends RuntimeException {
    public BlockedAccountException() {
        super("Your account has been blocked. Please contact the administrator");
    }
}
