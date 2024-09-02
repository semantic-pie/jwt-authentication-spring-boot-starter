package io.github.semanticpie.jwt_authentication_spring_boot_starter.security;

import lombok.NonNull;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;


@Component
public class JwtAuthConverter implements Converter<Jwt, Mono<AbstractAuthenticationToken>> {

    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    public Mono<AbstractAuthenticationToken> convert(@NonNull Jwt jwt) {
        Collection<GrantedAuthority> authorities = Stream.concat(
                jwtGrantedAuthoritiesConverter.convert(jwt).stream(),
                extractResourceRoles(jwt).stream()).collect(Collectors.toSet());
        User user = extractUserInfo(jwt);
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                user,
                null,
                authorities
        );
        SecurityContextHolder.getContext().setAuthentication(authToken);
        return Mono.just(authToken);
    }

    private User extractUserInfo(Jwt jwt) {
        UUID id = UUID.fromString(jwt.getClaim(SecurityUtil.SUB_UUID));
        String username = jwt.getClaim(SecurityUtil.PREFERRED_USERNAME);
        String email = jwt.getClaim(SecurityUtil.EMAIL);
        return User.builder()
                .id(id)
                .email(email)
                .username(username)
                .build();
    }

    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Map<String, Object> realmAccess = jwt.getClaim(SecurityUtil.REALM_ACCESS);
        Collection<String> realmRoles;
        if (realmAccess == null
                || (realmRoles = (Collection<String>) realmAccess.get(SecurityUtil.REALM_ROLES)) == null) {
            return Set.of();
        }
        return realmRoles.stream()
                .map(role -> new SimpleGrantedAuthority(SecurityUtil.ROLE_PREFIX + role))
                .collect(Collectors.toSet());
    }
}