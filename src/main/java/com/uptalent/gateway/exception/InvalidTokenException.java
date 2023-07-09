package com.uptalent.gateway.exception;

import static com.uptalent.gateway.exception.ExceptionConstant.INVALID_TOKEN_MESSAGE;

public class InvalidTokenException extends RuntimeException{
    public InvalidTokenException(){
        super(INVALID_TOKEN_MESSAGE);
    }
}
