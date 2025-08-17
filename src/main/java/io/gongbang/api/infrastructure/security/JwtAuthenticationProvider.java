package io.gongbang.api.infrastructure.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.util.Assert;


/**
 * Validate JwtAuthenticationToken and generate authenticated JwtAuthenticationToken with type
 */
@RequiredArgsConstructor
public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;

    private final JwtProvider jwtProvider;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.isInstanceOf(JwtAuthenticationToken.class, authentication,
                "Only JwtTokenAuthenticationToken is supported");

        String token = authentication.getCredentials().toString();
        jwtProvider.validateToken(token);
        String username = jwtProvider.getUsername(token);
        JwtType type = JwtType.valueOf(jwtProvider.getTokenType(token).toUpperCase());
        UserDetails user = this.userDetailsService.loadUserByUsername(username);

        return new JwtAuthenticationToken(user, token, type, user.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
