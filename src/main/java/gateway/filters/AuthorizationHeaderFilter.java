package gateway.filters;

import gateway.model.Response;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {
    private final Environment environment;

    public AuthorizationHeaderFilter(Environment environment) {
        super(Config.class);
        this.environment = environment;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            System.out.println(request.getURI());

            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)){
                return onError(exchange, "로그인 정보가 없습니다.", HttpStatus.UNAUTHORIZED);
            }

            String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            String jwt = authorizationHeader.replace("Bearer", "");

            if (!isJwtValid(jwt)){
                return onError(exchange, "로그인이 만료되었습니다.", HttpStatus.UNAUTHORIZED);
            }

            return chain.filter(exchange);
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String errorMessage, HttpStatus httpStatus) {
        log.error(errorMessage);
        Map<String, Object> resultMap = new LinkedHashMap<String, Object>();
        Response response = Response.builder()
                .statusCode(httpStatus.value())
                .status(httpStatus)
                .message(errorMessage)
                .result(resultMap).build();
        exchange.getResponse().setStatusCode(httpStatus);
        return exchange.getResponse()
        .setComplete()
        .then(Mono.fromRunnable(() -> {
            ResponseEntity responseEntity = ResponseEntity
                    .status(httpStatus.value())
                    .body(response);
            exchange.getResponse()
                    .getHeaders()
                    .setContentType(MediaType.APPLICATION_JSON);
            exchange.getResponse()
                    .writeWith(Mono.just(exchange.getResponse()
                    .bufferFactory()
                    .wrap(responseEntity.toString().getBytes())));
        }));
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity handleBadCredentialsException(BadCredentialsException e) {
        Response responseResult;
        Map<String, Object> resultMap = new LinkedHashMap<String, Object>();
        e.printStackTrace();
        responseResult = Response.builder()
                .statusCode(HttpStatus.UNAUTHORIZED.value())
                .status(HttpStatus.UNAUTHORIZED)
                .message("인증되지 않은 사용자입니다.")
                .result(resultMap).build();
        return ResponseEntity.internalServerError().body(responseResult);
    }

    private boolean isJwtValid(String jwt) {
    	boolean returnValue = true;
        String subject = null;
        String salt = environment.getProperty("jwt.secret.key");
        Key secretKey = Keys.hmacShaKeyFor(salt.getBytes(StandardCharsets.UTF_8));
        try {
            subject =
                //Jwts.parser().setSigningKey(environment.getProperty("jwt.secret.key"))
                Jwts.parserBuilder().setSigningKey(secretKey).build()
                .parseClaimsJws(jwt).getBody()
                .getSubject();
        } catch (Exception exception) {
            returnValue = false;
        }

        if (subject == null || subject.isEmpty()) {
            returnValue = false;
        }

        return returnValue;
    }

    public static class Config {}
}