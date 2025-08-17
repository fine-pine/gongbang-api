package io.gongbang.api.infrastructure.security;

import io.gongbang.api.member.MemberService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

import static io.jsonwebtoken.Jwts.SIG.HS256;

@Slf4j
@Component
// TODO: 싱글톤으로 사용해도 되는지, thread safe?
// TODO: 성능을 최적화하기 위해서는 log 수준을 확인한 후 로그를 출력해야 되는 것으로 알고 있는데, 적용하지 않는 이유?
public class JwtProvider {
    private static final String SCOPE_CLAIM_KEY = "scope";
    private static final String TOKEN_TYPE_CLAIM_KEY = "type";
    private static final String ACCESS_TOKEN_TYPE = "access";
    private static final String REFRESH_TOKEN_TYPE = "refresh";
    private static final String AUTHORITIES_DELIMITER = ",";
    private static final String AUTHORITY_PREFIX = "ROLE_";

    private final SecretKey secret;
    private final long accessTokenExpiration;
    private final long refreshTokenExpiration;
    private final MemberService memberService;

    public JwtProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-token-expiration:3600000}") long accessTokenExpiration,
            @Value("${jwt.refresh-token-expiration:604800000}") long refreshTokenExpiration,
            MemberService memberService) {
        this.secret = Keys.hmacShaKeyFor(secret.getBytes());
        this.accessTokenExpiration = accessTokenExpiration;
        this.refreshTokenExpiration = refreshTokenExpiration;
        this.memberService = memberService;
    }

    public String generateAccessToken(Authentication authentication) {
        String username = authentication.getName();
        String authorities = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .map(authority -> authority.substring(5))
                .collect(Collectors.joining(AUTHORITIES_DELIMITER));

        Date now = new Date();
        Date expiration = new Date(now.getTime() + accessTokenExpiration);

        return Jwts.builder()
                .subject(username)
                .claim(SCOPE_CLAIM_KEY, authorities)
                .claim(TOKEN_TYPE_CLAIM_KEY, ACCESS_TOKEN_TYPE)
                .issuedAt(now)
                .expiration(expiration)
                .signWith(secret, HS256)
                .compact();
    }

    public String generateAccessToken(UserDetails user) {
        String authorities = user.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .map(authority -> authority.substring(5))
                .collect(Collectors.joining(AUTHORITIES_DELIMITER));

        Date now = new Date();
        Date expiration = new Date(now.getTime() + accessTokenExpiration);

        return Jwts.builder()
                .subject(user.getUsername())
                .claim(SCOPE_CLAIM_KEY, authorities)
                .claim(TOKEN_TYPE_CLAIM_KEY, ACCESS_TOKEN_TYPE)
                .issuedAt(now)
                .expiration(expiration)
                .signWith(secret, HS256)
                .compact();
    }

    public String generateRefreshToken(String username) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + refreshTokenExpiration);

        return Jwts.builder()
                .subject(username)
                .claim(TOKEN_TYPE_CLAIM_KEY, REFRESH_TOKEN_TYPE)
                .issuedAt(now)
                .expiration(expiration)
                .signWith(secret, HS256)
                .compact();
    }

    public String refreshAccessToken(String refreshToken) {
        if (validateToken(refreshToken) && isRefreshToken(refreshToken)) {
            String username = getUsername(refreshToken);
            UserDetails user = memberService.loadUserByUsername(username);
            return generateAccessToken(user);
        }

        throw new JwtException("Invalid refresh token");
    }

    public boolean validateToken(String token) {
        getClaims(token);
        return true;
    }

    public String getUsername(String token) {
        return getClaims(token).getSubject();
    }

    public Collection<GrantedAuthority> getAuthorities(String token) {
        String[] authorities = getClaims(token)
                .get(SCOPE_CLAIM_KEY, String.class)
                .split(AUTHORITIES_DELIMITER);

        Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        for (String authority : authorities) {
            grantedAuthorities.add(new SimpleGrantedAuthority(AUTHORITY_PREFIX + authority));
        }
        return grantedAuthorities;
    }

    public Date getExpiration(String token) {
        return getClaims(token).getExpiration();
    }

    public String getTokenType(String token) {
        return getClaims(token).get(TOKEN_TYPE_CLAIM_KEY, String.class);
    }

    public Claims getClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(secret)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException ex) {
            log.error("Expired token: {}", ex.getMessage());
        } catch (UnsupportedJwtException ex) {
            log.error("Unsupported token: {}", ex.getMessage());
        } catch (JwtException | IllegalArgumentException ex) {
            log.error("Invalid token: {}", ex.getMessage());
        } catch (Exception ex) {
            log.error("Server error: {}", ex.getMessage());
        }

        throw new JwtException("Invalid token");
    }

    public boolean isTokenExpired(String token) {
        Date expiration = getExpiration(token);
        return expiration != null && expiration.before(new Date());
    }

    public boolean isAccessToken(String token) {
        return ACCESS_TOKEN_TYPE.equals(getTokenType(token));
    }

    public boolean isRefreshToken(String token) {
        return REFRESH_TOKEN_TYPE.equals(getTokenType(token));
    }
}