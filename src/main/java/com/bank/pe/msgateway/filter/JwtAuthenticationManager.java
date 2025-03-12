package com.bank.pe.msgateway.filter;

import com.bank.pe.msgateway.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.util.ArrayList;

@Component
public class JwtAuthenticationManager implements ReactiveAuthenticationManager {

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        String authToken = authentication.getCredentials().toString();
        try {
            String username = jwtUtil.extractUsername(authToken);


            if (username != null && jwtUtil.validateToken(authToken, new User(username, "", new ArrayList<>()))) {
                return Mono.just(new UsernamePasswordAuthenticationToken(username, authToken, new ArrayList<>()));
            } else {
                return Mono.empty();
            }
        } catch (RuntimeException e) {
            return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid JWT token"));
        }
    }
}
