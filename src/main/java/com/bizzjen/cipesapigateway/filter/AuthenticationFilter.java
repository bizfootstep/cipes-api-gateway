package com.bizzjen.cipesapigateway.filter;

import com.bizzjen.cipesapigateway.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;


@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    @Autowired
    private RouteValidator validator;

    @Autowired
    private JwtUtil jwtUtil;

//    @Autowired
//    private RestTemplate restTemplate;

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            if (validator.isSecured.test(exchange.getRequest())) {
                //header contains token or not
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    throw new RuntimeException("Missing authorization header");
                }
                String authheader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                if (authheader != null && authheader.startsWith("Bearer ")) {
                    authheader = authheader.substring(7);
                }
                try {
//                    restTemplate.getForObject("http://CIPES-AUTH-SERVICE/validate?token" + authheader, String.class);
                    jwtUtil.validateToken(authheader);
                } catch (Exception e) {

                    throw new RuntimeException("unauthorized access to application");
                }

            }
            return chain.filter(exchange);
        });
    }

    public static class Config {

    }
}
