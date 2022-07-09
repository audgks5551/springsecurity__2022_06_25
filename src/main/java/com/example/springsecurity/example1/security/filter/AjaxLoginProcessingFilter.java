package com.example.springsecurity.example1.security.filter;

import com.example.springsecurity.example1.form.LoginForm;
import com.example.springsecurity.example1.security.token.AjaxAuthenticationToken;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * AjaxLoginProcessingFilter는 UsernamePasswordAuthenticationFilter를 모방함
 */
public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    public static final String AJAX_USERNAME_KEY = "username";

    public static final String AJAX_PASSWORD_KEY = "password";

    private static final AntPathRequestMatcher AJAX_DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/api/login",
            "POST");

    private boolean postOnly = true;

    private String usernameParameter = AJAX_USERNAME_KEY;

    private String passwordParameter = AJAX_PASSWORD_KEY;
    private ObjectMapper objectMapper = new ObjectMapper();

    public AjaxLoginProcessingFilter() {
        super(AJAX_DEFAULT_ANT_PATH_REQUEST_MATCHER);
    }

    public AjaxLoginProcessingFilter(AuthenticationManager authenticationManager) {
        super(AJAX_DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        if (this.postOnly && !request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        if (isAjax(request)) {
            throw new IllegalStateException("Authentication is not supported");
        }
        Map<String, Object> parameters = objectMapper.readValue(request.getReader(), new TypeReference<Map<String, Object>>() {});

        String username = parameters.get(this.usernameParameter).toString();
        username = (username != null) ? username.trim() : "";
        String password = parameters.get(this.passwordParameter).toString();
        password = (password != null) ? password : "";


        if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
            throw new IllegalArgumentException("Username or Password is empty");
        }

        AjaxAuthenticationToken ajaxAuthenticationToken = new AjaxAuthenticationToken(username, password);

        return getAuthenticationManager().authenticate(ajaxAuthenticationToken);
    }

    private boolean isAjax(HttpServletRequest request) {

        if (!"XMLHttpRequest".equals(request.getHeader("X-Requested-With"))) {
            return true;
        }

        return false;
    }

    public void setUsernameParameter(String usernameParameter) {
        Assert.hasText(usernameParameter, "Username parameter must not be empty or null");
        this.usernameParameter = usernameParameter;
    }

    public void setPasswordParameter(String passwordParameter) {
        Assert.hasText(passwordParameter, "Password parameter must not be empty or null");
        this.passwordParameter = passwordParameter;
    }

    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }

    public final String getUsernameParameter() {
        return this.usernameParameter;
    }

    public final String getPasswordParameter() {
        return this.passwordParameter;
    }
}
