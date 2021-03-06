package com.example.springsecurity.example1.security.configs;

import com.example.springsecurity.example1.security.handler.FormAccessDeniedHandler;
import com.example.springsecurity.example1.security.handler.FormAuthenticationFailureHandler;
import com.example.springsecurity.example1.security.handler.FormAuthenticationSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * spring security 환경 설정 클래스
 */
@Order(1)
@EnableWebSecurity
public class FormSecurityConfig {
    private AuthenticationDetailsSource authenticationDetailsSource;
    private AuthenticationProvider authenticationProvider;

    @Autowired
    public FormSecurityConfig(
            AuthenticationDetailsSource authenticationDetailsSource,
            @Qualifier("FormAuthenticationProvider") AuthenticationProvider authenticationProvider) {
        this.authenticationDetailsSource = authenticationDetailsSource;
        this.authenticationProvider = authenticationProvider;
    }

    @Bean
    public SecurityFilterChain formFilterChain(HttpSecurity http) throws Exception {

        http
                /**
                 * 인가
                 */
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests
                                .antMatchers("/", "/users", "/login*").permitAll()
                                .antMatchers("/myPage").hasRole("USER")
                                .antMatchers("/message").hasRole("MANAGER")
                                .antMatchers("/config").hasRole("ADMIN")
                                .anyRequest().authenticated()
                )
                /**
                 * 인증
                 */
                .formLogin(formLogin ->
                        formLogin
                                .loginPage("/login")
                                .loginProcessingUrl("/login_proc")
                                .usernameParameter("username")
                                .passwordParameter("password")
                                .defaultSuccessUrl("/")
                                .failureUrl("/login")
                                .authenticationDetailsSource(authenticationDetailsSource)
                                .successHandler(formAuthenticationSuccessHandler())
                                .failureHandler(formAuthenticationFailureHandler())
                                .permitAll()
                )
                /**
                 * 403 에러처리
                 */
                .exceptionHandling(httpSecurityExceptionHandlingConfigurer ->
                        httpSecurityExceptionHandlingConfigurer
                                .accessDeniedHandler(accessDeniedHandler())
                )
                .authenticationProvider(authenticationProvider);

        return http.build();
    }

    /**
     * 권한 없는 페이지에 들어왔을 때의 페이지를 설정
     */
    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        FormAccessDeniedHandler customAccessDeniedHandler = new FormAccessDeniedHandler();
        customAccessDeniedHandler.setErrorPage("/denied");
        return customAccessDeniedHandler;
    }

    /**
     * static 디렉터리의 하위 파일 목록은 무시
     *  - 보안 필터를 거치지 않는다
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations())
                .antMatchers("/error");
    }

    /**
     * formAuthenticationSuccessHandler 빈 등록
     */
    @Bean
    public AuthenticationSuccessHandler formAuthenticationSuccessHandler() {
        return new FormAuthenticationSuccessHandler();
    }

    /**
     * formAuthenticationFailureHandler 빈 등록
     */
    @Bean
    public AuthenticationFailureHandler formAuthenticationFailureHandler() {
        return new FormAuthenticationFailureHandler();
    }
}
