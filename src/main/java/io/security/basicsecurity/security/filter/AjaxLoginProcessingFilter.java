package io.security.basicsecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.basicsecurity.domain.AccountDto;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//
public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private ObjectMapper objectMapper = new ObjectMapper();

    // 사용자가 url로 요청 했을 때 아래의 url정보와 매칭이 되면 필드가 작동되록 한다.
    protected AjaxLoginProcessingFilter() {
        super(new AntPathRequestMatcher("/api/login"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        if(!isAjax(request)){
            throw new IllegalStateException("Authentication is not supported");
        }

        // url 매핑 조건과 요청방식 조건이 통과되면 ~
        AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);
        //if()

        return null;
    }

    // 요청의 헤더의 값을 확인하여 요청 방식이 ajax인지 확인한다.
    private boolean isAjax(HttpServletRequest request) {
        if("XMLHttpRequest".equals(request.getHeader("X-Requested-with"))){
            return true;
        }
        return false;
    }
}
