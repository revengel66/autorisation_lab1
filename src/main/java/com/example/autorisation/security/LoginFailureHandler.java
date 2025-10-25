package com.example.autorisation.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class LoginFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final LoginAttemptService loginAttemptService;

    public LoginFailureHandler(LoginAttemptService loginAttemptService) {
        this.loginAttemptService = loginAttemptService;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        String username = request.getParameter("username");

        if (exception instanceof LockedException) {
            getRedirectStrategy().sendRedirect(request, response, "/login?blocked");
            return;
        }
        if (exception instanceof UsernameNotFoundException) {
            getRedirectStrategy().sendRedirect(request, response, "/login?userNotFound");
            return;
        }

        if (exception instanceof BadCredentialsException) {
            int attemptsLeft = loginAttemptService.recordFailedAttempt(username);
            if (attemptsLeft <= 0) {
                getRedirectStrategy().sendRedirect(request, response, "/login?terminated");
            } else {
                getRedirectStrategy().sendRedirect(request, response,
                        "/login?badCredentials&attemptsLeft=" + attemptsLeft);
            }
            return;
        }

        getRedirectStrategy().sendRedirect(request, response, "/login?error");
    }
}
