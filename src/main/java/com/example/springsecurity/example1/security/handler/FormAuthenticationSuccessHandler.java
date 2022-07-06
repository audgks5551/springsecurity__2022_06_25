package com.example.springsecurity.example1.security.handler;

import com.example.springsecurity.example1.domain.Account;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;

public class FormAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private RequestCache requestCache = new HttpSessionRequestCache();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        SavedRequest savedRequest = requestCache.getRequest(request, response);

        Account account = (Account) authentication.getPrincipal();
        String username = account.getUsername();

        String message = String.format("%s님 환영합니다", username);
        message = URLEncoder.encode(message, "UTF-8");
        if (savedRequest != null) {
            String redirectUrl = savedRequest.getRedirectUrl();
            getRedirectStrategy().sendRedirect(request, response, String.format("%s?success=true&message=%s", redirectUrl, message));
        } else {
            getRedirectStrategy().sendRedirect(request, response, String.format("%s?success=true&message=%s", getDefaultTargetUrl(), message));
        }
    }
}
