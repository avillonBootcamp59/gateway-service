package com.bank.pe.msgateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.util.Base64;
@Slf4j
@Component
public class JwtFilter extends AbstractGatewayFilterFactory<JwtFilter.Config> {

    @Value("${key_token}")
    private String privateKey;

    public JwtFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            // Verifica si la cabecera Authorization está presente
            if (!request.getHeaders().containsKey("Authorization")) {
                return onError(exchange, "No authorization header", HttpStatus.UNAUTHORIZED);
            }

            // Obtiene el token de la cabecera
            String token = request.getHeaders().getOrEmpty("Authorization").get(0);
            if (token == null || !token.startsWith("Bearer ")) {
                return onError(exchange, "Invalid token format", HttpStatus.UNAUTHORIZED);
            }

            // Elimina el prefijo "Bearer " del token
            token = token.substring(7);

            // Valida el token
            if (!isTokenValid(token)) {
                return onError(exchange, "Invalid token", HttpStatus.UNAUTHORIZED);
            }

            // Propaga la solicitud al siguiente filtro o microservicio
            return chain.filter(exchange);
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String error, HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        return response.setComplete();
    }

    private boolean isTokenValid(String token) {
        try {
            System.out.println("TOKEN RECIBIDO EN EL GATEWAY: " + token);
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(Base64.getDecoder().decode(privateKey))
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            return true;
        } catch (Exception e) {
            System.err.println("Error validando token en Gateway: " + e.getMessage());
            return false;
        }
    }


    public static class Config {
        // Configuración adicional si es necesario
    }
}