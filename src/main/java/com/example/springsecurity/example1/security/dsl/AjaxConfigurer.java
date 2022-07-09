package com.example.springsecurity.example1.security.dsl;

import com.example.springsecurity.example1.security.filter.AjaxLoginProcessingFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class AjaxConfigurer <H extends HttpSecurityBuilder<H>> extends
        AbstractAuthenticationFilterConfigurer<H, AjaxConfigurer<H>, AjaxLoginProcessingFilter> {

    private AuthenticationSuccessHandler authenticationSuccessHandler;
    private AuthenticationFailureHandler authenticationFailureHandler;
    private AuthenticationProvider authenticationProvider;

    public AjaxConfigurer() {
        super(new AjaxLoginProcessingFilter(), null);
        usernameParameter("username");
        passwordParameter("password");
    }

    @Override
    protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
        return new AntPathRequestMatcher(loginProcessingUrl, "POST");
    }

    @Override
    public void init(H http) throws Exception {
        super.init(http);
    }

    @Override
    public void configure(H http) throws Exception {
        http.authenticationProvider(authenticationProvider);

        getAuthenticationFilter().setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
        getAuthenticationFilter().setAuthenticationSuccessHandler(authenticationSuccessHandler);
        getAuthenticationFilter().setAuthenticationFailureHandler(authenticationFailureHandler);

        SessionAuthenticationStrategy sessionAuthenticationStrategy = http
                .getSharedObject(SessionAuthenticationStrategy.class);
        if (sessionAuthenticationStrategy != null) {
            getAuthenticationFilter().setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
        }
        RememberMeServices rememberMeServices = http.getSharedObject(RememberMeServices.class);
        if (rememberMeServices != null) {
            getAuthenticationFilter().setRememberMeServices(rememberMeServices);
        }

        http.addFilterBefore(getAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    public AjaxConfigurer<H> usernameParameter(String usernameParameter) {
        getAuthenticationFilter().setUsernameParameter(usernameParameter);
        return this;
    }

    public AjaxConfigurer<H> passwordParameter(String passwordParameter) {
        getAuthenticationFilter().setPasswordParameter(passwordParameter);
        return this;
    }

    private String getUsernameParameter() {
        return getAuthenticationFilter().getUsernameParameter();
    }

    private String getPasswordParameter() {
        return getAuthenticationFilter().getPasswordParameter();
    }

    @Override
    public AjaxConfigurer<H> loginPage(String loginPage) {
        return super.loginPage(loginPage);
    }

    public AjaxConfigurer<H> successHandlerAjax(AuthenticationSuccessHandler authenticationSuccessHandler) {
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        return this;
    }

    public AjaxConfigurer<H> failureHandlerAjax(AuthenticationFailureHandler authenticationFailureHandler) {
        this.authenticationFailureHandler = authenticationFailureHandler;
        return this;
    }

    public AjaxConfigurer<H> authenticationProvider(AuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
        return this;
    }
}
