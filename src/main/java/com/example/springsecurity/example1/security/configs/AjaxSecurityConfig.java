package com.example.springsecurity.example1.security.configs;

import com.example.springsecurity.example1.security.common.AjaxAccessDeniedHandler;
import com.example.springsecurity.example1.security.common.AjaxLoginAuthenticationEntryPoint;
import com.example.springsecurity.example1.security.dsl.AjaxConfigurer;
import com.example.springsecurity.example1.security.dsl.AjaxLoginConfigurer;
import com.example.springsecurity.example1.security.handler.AjaxAuthenticationFailureHandler;
import com.example.springsecurity.example1.security.handler.AjaxAuthenticationSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

import static org.springframework.http.HttpMethod.*;

@Order(0)
@EnableWebSecurity
public class AjaxSecurityConfig {
    private UserDetailsService userDetailsService;
    private PasswordEncoder passwordEncoder;
    private AuthenticationProvider authenticationProvider;

    @Autowired
    public AjaxSecurityConfig(
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder,
            @Qualifier("AjaxAuthenticationProvider") AuthenticationProvider authenticationProvider) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.authenticationProvider = authenticationProvider;
    }

    @Bean
    public SecurityFilterChain ajaxFilterChain(HttpSecurity http) throws Exception {

        http
                /**
                 * 인가
                 */
                .antMatcher("/api/**")
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests
                                .antMatchers("/api/messages").hasRole("MANAGER")
                                .anyRequest().authenticated()
                )
                .exceptionHandling(httpSecurityExceptionHandlingConfigurer ->
                        httpSecurityExceptionHandlingConfigurer
                                .authenticationEntryPoint(new AjaxLoginAuthenticationEntryPoint())
                                .accessDeniedHandler(new AjaxAccessDeniedHandler())
                )
                /**
                 * 인증
                 *  - formLogin 처럼 DSL 제작
                 *  TODO
                 *   - 람다 형식으로 변환 해야함
                 */
                .apply(new AjaxConfigurer<>())
                .loginPage("/api/login")
                .loginProcessingUrl("/api/login")
                .usernameParameter("username")
                .passwordParameter("password")
                .authenticationProvider(authenticationProvider)
                .successHandlerAjax(ajaxAuthenticationSuccessHandler())
                .failureHandlerAjax(ajaxAuthenticationFailureHandler())
                .permitAll();

        return http.build();
    }

    /**
     * ajaxAuthenticationSuccessHandler 빈 등록
     */
    @Bean
    public AuthenticationSuccessHandler ajaxAuthenticationSuccessHandler() {
        return new AjaxAuthenticationSuccessHandler();
    }

    /**
     * ajaxAuthenticationFailureHandler 빈 등록
     */
    @Bean
    public AuthenticationFailureHandler ajaxAuthenticationFailureHandler() {
        return new AjaxAuthenticationFailureHandler();
    }
}
