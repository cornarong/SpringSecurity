package io.security.basicsecurity.security.handler;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// # 인증 거부 핸들러
// 인증을 받은 사용자가 자원에 접근할 수 있는 권한이 충분하지 않은 경우 필터가 해당 클래스로 전달한다.
// 반대로 인증을 받지않은 사용자가 자원에 접근할 경우 = AjaxLoginUrlAuthenticationEntryPoint
public class AjaxAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access is denied");
    }
}
