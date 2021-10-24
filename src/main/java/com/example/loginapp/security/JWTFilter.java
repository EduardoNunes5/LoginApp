package com.example.loginapp.security;

import com.example.loginapp.services.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JWTFilter extends OncePerRequestFilter {

    @Autowired
    private JWTService jwtService;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String username = "";
        String jwt = "";

        String authHeader = request.getHeader("Authorization");
        if(isTokenPresent(authHeader)){
            jwt = authHeader.substring(7);
            username = jwtService.getUsernameFromToken(jwt);
        } else{
            logger.warn("Jwt token does not begin with Bearer String or not provided");
        }
        if(!isUsernameInContext(username)){
            addUserToContext(request, username, jwt);
        }

        filterChain.doFilter(request, response);
    }

    private boolean isTokenPresent(String authHeader) {
        return authHeader != null || authHeader.startsWith("Bearer ");
    }

    private void addUserToContext(HttpServletRequest request, String username, String jwtToken) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if(jwtService.validateToken(jwtToken, userDetails)){
            UsernamePasswordAuthenticationToken userToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            userToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(userToken);
        }
    }

    private boolean isUsernameInContext(String username) {
        return username != null && SecurityContextHolder.getContext().getAuthentication() == null;
    }

}
