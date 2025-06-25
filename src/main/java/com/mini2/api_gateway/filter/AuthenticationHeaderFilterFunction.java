package com.mini2.api_gateway.filter;

import com.mini2.api_gateway.security.jwt.authentication.UserPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.servlet.function.ServerRequest;

import java.util.function.Function;

public class AuthenticationHeaderFilterFunction {
    public static Function<ServerRequest, ServerRequest> addHeader() {
        return request -> {
            ServerRequest.Builder requestBuilder = ServerRequest.from(request);

            Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            if( principal instanceof UserPrincipal userPrincipal) {
                requestBuilder.header("X-Auth-UserId",userPrincipal.getUserId());
            }

            HttpServletRequest servletRequest = request.servletRequest();
            String userAgent = servletRequest.getHeader("User-Agent");

            String device;
            if (userAgent != null) {
                if (userAgent.contains("Android") || userAgent.contains("iPhone")) {
                    device = "MOBILE";
                } else if (userAgent.contains("Windows") || userAgent.contains("Macintosh")) {
                    device = "WEB";
                } else {
                    device = "UNKNOWN";
                }
            } else {
                device = "UNKNOWN";
            }

            requestBuilder.header("X-Client-Device", device);

            return requestBuilder.build();
        };
    }
}
