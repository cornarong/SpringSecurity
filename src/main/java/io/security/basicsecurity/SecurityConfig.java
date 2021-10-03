package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity // 필수 설정
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 인가 정책
        http
                .authorizeRequests()
                .anyRequest().authenticated();
        // 인증 정책
        http
                .formLogin() // formLogin방식
//                .loginPage("/loginPage") // 로그인 페이지
                .defaultSuccessUrl("/") // 로그인 성공시 url
                .failureUrl("/loginPage") // 로그인 실패시 url
                .usernameParameter("userId") // form의 id 파라미터명
                .passwordParameter("passwd") // form의 password 파라미터명
                .loginProcessingUrl("/login_proc") // form의 action 경로
                .successHandler(new AuthenticationSuccessHandler() { // 성공시 success 핸들러를 호출한다. 추가로 사용해보자
                    // 로그인 성공시 authentication 정보를 매개변수로 -
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication : " + authentication.getName());
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() { // 실패시 fail 핸들러를 호출한다. 추가로 사용해보자
                    // 로그인 실패시 exception 정보를 매개변수로 -
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception : " + exception.getMessage());
                        response.sendRedirect("/loginPage");
                    }
                })
                .permitAll();

    }
}
