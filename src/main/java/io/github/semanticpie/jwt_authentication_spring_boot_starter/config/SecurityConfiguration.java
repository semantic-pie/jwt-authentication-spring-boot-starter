package io.github.semanticpie.jwt_authentication_spring_boot_starter.config;

import io.github.semanticpie.jwt_authentication_spring_boot_starter.security.JwtAuthConverter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SecurityConfiguration {
    @Bean
    @ConditionalOnMissingBean
    JwtAuthConverter jwtAuthConverter(){
        return new JwtAuthConverter();
    }
}
