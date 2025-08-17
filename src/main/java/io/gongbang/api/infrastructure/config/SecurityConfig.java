package io.gongbang.api.infrastructure.config;

import io.gongbang.api.infrastructure.security.JwtAuthenticationProvider;
import io.gongbang.api.infrastructure.security.JwtProvider;
import io.gongbang.api.infrastructure.security.UsernamePasswordAuthenticationSuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Collections;
import java.util.List;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    // TODO: CustomProvider 빈 선언시 해당 AuthenticationManager가 동작하지 않는 것을 보았다.
    @Bean
    public AuthenticationManager authenticationManagerBean(
            UserDetailsService userService,
            PasswordEncoder passwordEncoder,
            JwtProvider jwtProvider) {

        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(userService);
        authProvider.setPasswordEncoder(passwordEncoder);
        JwtAuthenticationProvider jwtAuthenticationProvider = new JwtAuthenticationProvider(userService, jwtProvider);
        return new ProviderManager(authProvider, jwtAuthenticationProvider);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    UsernamePasswordAuthenticationSuccessHandler usernamePasswordAuthenticationSuccessHandler(JwtProvider jwtProvider) {
        return new UsernamePasswordAuthenticationSuccessHandler(jwtProvider);
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(
            HttpSecurity http,
            UsernamePasswordAuthenticationSuccessHandler usernamePasswordAuthenticationSuccessHandler
    ) throws Exception {
        http
                .sessionManagement(sc -> sc.sessionCreationPolicy(STATELESS))
                .csrf(AbstractHttpConfigurer::disable)
                .headers(hc -> hc.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
                .cors(cc -> cc.configurationSource(req -> {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOrigins(List.of(
                            "http://localhost:3000",
                            "https://localhost:3000"
                    ));
                    config.setAllowedMethods(Collections.singletonList("*"));
                    config.setAllowedHeaders(Collections.singletonList("*"));
                    config.setExposedHeaders(List.of("Authorization"));
                    config.setAllowCredentials(true);
                    config.setMaxAge(3600L);
                    return config;
                }))
                .formLogin(fc -> fc
                        .successHandler(usernamePasswordAuthenticationSuccessHandler))
                .authorizeHttpRequests(arc -> arc
                        .requestMatchers(GET, "/**").permitAll()
                        .requestMatchers(POST, "/v1/members").permitAll()
                        .requestMatchers("/resources/**", "/static/**").permitAll()
                        .requestMatchers("/h2-console/**").permitAll()
                        .anyRequest().authenticated());
        return http.build();
    }
}
