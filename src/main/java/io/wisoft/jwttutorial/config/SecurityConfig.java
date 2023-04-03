package io.wisoft.jwttutorial.config;

import io.wisoft.jwttutorial.jwt.JwtAccessDeniedHandler;
import io.wisoft.jwttutorial.jwt.JwtAuthenticationEntryPoint;
import io.wisoft.jwttutorial.jwt.JwtSecurityConfig;
import io.wisoft.jwttutorial.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    public SecurityConfig(
            final TokenProvider tokenProvider,
            final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            final JwtAccessDeniedHandler jwtAccessDeniedHandler) {

        this.tokenProvider = tokenProvider;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * WebSecurityConfigurerAdapter is predicate
     * reference : https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter
     */
    @Bean
    public SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {
        http
                .csrf().disable()  //token을 사용하는 방식이기 때문에 csrf를 disable로

                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                .and()
                .headers()
                .frameOptions()
                .sameOrigin()

                .and()
                .authorizeRequests()
                .requestMatchers("/api/hello").permitAll() //anyMatchers is predicated
                .requestMatchers("/h2-console/**").permitAll() //anyMatchers is predicated
                .requestMatchers("/favicon.ico").permitAll() //anyMatchers is predicated
                .requestMatchers("/api/login").permitAll() //anyMatchers is predicated
                .requestMatchers("/api/signup").permitAll() //anyMatchers is predicated
                .anyRequest().authenticated()

                .and()
                .apply(new JwtSecurityConfig(tokenProvider));

        return http.build();
    }
}
