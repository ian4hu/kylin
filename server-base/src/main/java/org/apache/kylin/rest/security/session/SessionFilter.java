package org.apache.kylin.rest.security.session;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.session.MapSession;
import org.springframework.session.web.http.SessionRepositoryFilter;
import org.springframework.web.filter.OncePerRequestFilter;

public class SessionFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        SessionRepositoryFilter<MapSession> delegate = new SessionRepositoryFilter<>(new CookieBasedSessionRepository(request, response, "kylin-sess"));
        delegate.setServletContext(getServletContext());
        delegate.doFilter(request, response, filterChain);
    }
}
