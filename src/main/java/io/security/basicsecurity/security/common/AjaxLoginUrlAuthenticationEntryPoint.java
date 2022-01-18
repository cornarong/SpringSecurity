package io.security.basicsecurity.security.common;


import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 인증을 받지 않은 상태로 자원에 접근한 경우 필터가 해당 클래스로 전달한다.
// 반대로 인증을 받은 사용자가 자원에 접근할 권한이 없을 경우 = AjaxAccessDeniedHandler
public class AjaxLoginUrlAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "UnAuthorized");

    }
}
