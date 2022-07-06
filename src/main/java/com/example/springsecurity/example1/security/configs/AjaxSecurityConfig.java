package com.example.springsecurity.example1.security.configs;

import com.example.springsecurity.example1.security.filter.AjaxLoginProcessingFilter;
import com.example.springsecurity.example1.security.handler.AjaxAuthenticationFailureHandler;
import com.example.springsecurity.example1.security.handler.AjaxAuthenticationSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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
                .csrf().disable()
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests
                                .anyRequest().authenticated()
                )
                /**
                 * ajax 인증 처리 필터를 UsernamePasswordAuthenticationFilter 앞에 위치시키기
                 */
                .addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
        ;

        return http.build();
    }

    /**
     * ajaxLoginProcessingFilter 빈 등록
     */
    public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() throws Exception {
        AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter("/api/login");
        ajaxLoginProcessingFilter.setAuthenticationManager(new ProviderManager(authenticationProvider));
        ajaxLoginProcessingFilter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler());
        ajaxLoginProcessingFilter.setAuthenticationFailureHandler(ajaxAuthenticationFailureHandler());
        return ajaxLoginProcessingFilter;
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
