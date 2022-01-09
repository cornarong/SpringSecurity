package io.security.basicsecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.basicsecurity.domain.AccountDto;
import io.security.basicsecurity.security.token.AjaxAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.thymeleaf.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 인증 필터 - AjaxAuthenticationFilter
public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private ObjectMapper objectMapper = new ObjectMapper();

    // 사용자가 url로 요청 했을 때 아래의 url정보와 매칭이 되면 필드가 작동되록 한다.
    public AjaxLoginProcessingFilter() {
        super(new AntPathRequestMatcher("/api/login"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        // 요청된 url 경로가 위의 "/api/login"과 매칭되면 ~
        // * 요청방식 확인
        if(!isAjax(request)){
            throw new IllegalStateException("Authentication is not supported");
        }

        // 요청방식 확인이 통과되면 ~
        // * id/password 확인
        AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);
        if(StringUtils.isEmpty(accountDto.getUsername()) || StringUtils.isEmpty(accountDto.getPassword())){
            throw new IllegalArgumentException("Username or Password is empty");
        }

        // id/password의 확인이 통과 되면 ~
        AjaxAuthenticationToken ajaxAuthenticationToken = new AjaxAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());

        return getAuthenticationManager().authenticate(ajaxAuthenticationToken);
    }

    // 요청의 헤더의 값을 확인하여 요청 방식이 ajax인지 확인한다.
    private boolean isAjax(HttpServletRequest request) {
        if("XMLHttpRequest".equals(request.getHeader("X-Requested-with"))){
            return true;
        }
        return false;
    }
}
