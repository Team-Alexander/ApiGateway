package io.github.uptalent.gateway.exception.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.uptalent.gateway.exception.BlockedAccountException;
import io.github.uptalent.gateway.exception.InvalidTokenException;
import io.github.uptalent.gateway.model.ErrorResponse;
import io.github.uptalent.gateway.exception.ExceptionConstant;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.support.NotFoundException;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebExceptionHandler;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.ConnectException;

@Component
@Order(-2)
@Slf4j
@RequiredArgsConstructor
public class GlobalExceptionHandler implements WebExceptionHandler {
    private final ObjectMapper objectMapper;

    @Override
    @NonNull
    public Mono<Void> handle(@NonNull ServerWebExchange exchange, @NonNull Throwable ex) {
        if (ex instanceof InvalidTokenException) {
            return error(exchange, HttpStatus.UNAUTHORIZED, ex.getMessage());
        } else if (ex instanceof BlockedAccountException) {
            return error(exchange, HttpStatus.FORBIDDEN, ex.getMessage());
        } else if ((ex instanceof ResponseStatusException
                && ((ResponseStatusException) ex).getStatusCode() == HttpStatus.NOT_FOUND)
                || ex instanceof NotFoundException) {
            return error(exchange, HttpStatus.NOT_FOUND, ExceptionConstant.NOT_FOUND_MESSAGE);
        } else if(ex instanceof WebClientRequestException || ex instanceof ConnectException
                || ex.getCause() instanceof ConnectException){
            return error(exchange, HttpStatus.SERVICE_UNAVAILABLE, ExceptionConstant.SERVICE_UNAVAILABLE_MESSAGE);
        } else {
            log.error("Internal Server Error", ex);
            return error(exchange, HttpStatus.INTERNAL_SERVER_ERROR, ExceptionConstant.INTERNAL_SERVER_ERROR_MESSAGE);
        }
    }

    @SneakyThrows
    private Mono<Void> error(ServerWebExchange exchange, HttpStatus httpStatus, String errorText) {
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        exchange.getResponse().setStatusCode(httpStatus);
        ErrorResponse errorResponse = new ErrorResponse(errorText);

        byte[] bytes = objectMapper.writeValueAsBytes(errorResponse);
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);

        return exchange.getResponse().writeWith(Flux.just(buffer));
    }
}
