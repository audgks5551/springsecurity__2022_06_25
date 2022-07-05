package com.example.springsecurity.example1.security.configs;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * spring security 환경 설정 클래스
 */
@Configuration
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final AuthenticationDetailsSource authenticationDetailsSource;
    private final AuthenticationSuccessHandler authenticationSuccessHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                /**
                 * 인가
                 */
                .authorizeRequests((authorizeRequests) -> authorizeRequests
                        .antMatchers("/", "/users").permitAll()
                        .antMatchers("/myPage").hasRole("USER")
                        .antMatchers("/message").hasRole("MANAGER")
                        .antMatchers("/config").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                /**
                 * 인증
                 */
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .usernameParameter("username")
                .passwordParameter("password")
                .defaultSuccessUrl("/")
                .failureUrl("/login")
                .authenticationDetailsSource(authenticationDetailsSource)
                .successHandler(authenticationSuccessHandler)
                .permitAll();

        return http.build();
    }

    /**
     * 패스워드 암호화
     *  - 인코딩시 BCryptPasswordEncoder 방식 사용
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * static 디렉터리의 하위 파일 목록은 무시
     *  - 보안 필터를 거치지 않는다
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }
}
