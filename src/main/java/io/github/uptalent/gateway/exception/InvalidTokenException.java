package io.github.uptalent.gateway.exception;

public class InvalidTokenException extends RuntimeException{
    public InvalidTokenException(){
        super(ExceptionConstant.INVALID_TOKEN_MESSAGE);
    }
}
