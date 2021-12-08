package io.security.basicsecurity;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity // 필수 설정
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private final UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 사이트간 요청 위조 - CSRF
        http
                .csrf();
//                .disable(); // csrf설정은 기본적으로 활성화 되어있음 사용하지 않을 경우에만 선언해주면 된다.
        // 인가 정책
        http
                .authorizeRequests()
                .anyRequest().authenticated();
//                .anyRequest().permitAll();
        // 인증 정책
        http
                .formLogin() // formLogin방식
//                    .loginPage("/loginPage") // 로그인 페이지
                    .permitAll()
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
                    .and()
                .logout()
                    .logoutUrl("/logout") // 시큐리티는 원칙적으로 logout 처리를 post 방식으로 처리해야 한다.
                    .logoutSuccessUrl("/login")
                    .addLogoutHandler(new LogoutHandler() {
                        @Override
                        public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                            HttpSession session = request.getSession();
                            session.invalidate();
                        }
                    })
                    .logoutSuccessHandler(new LogoutSuccessHandler() {
                        @Override
                        public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                            response.sendRedirect("/login");
                        }
                    })
                    .deleteCookies("remember-me")
                    .and()
                .rememberMe()
                    .rememberMeParameter("remember")
                    .tokenValiditySeconds(3600)
                    .alwaysRemember(false)
                    .userDetailsService(userDetailsService)
                    .and()
                .sessionManagement()
                    .sessionFixation().changeSessionId() // 기본 설정 되어 있음. 요청 할 떄 마다 세션 ID를 새로 공급 받아 공격자로부터 세션을 공유하지 못하도록 방어한다.
                    .maximumSessions(1)
                    // 동시 세션 제어
                    .maxSessionsPreventsLogin(false) // default : false -> 기존 사용중인 사용자는 세션을 만료시키고 새로 로그인한 사용자에게 세션이 주어준다.
                    // 세션 고정 보호
        ;
        // 동시 세션 제어
        http.sessionManagement()
                .maximumSessions(1) // 최대 허용 가능 세션 수, -1 : 무제한 로그인 세션 허용
                .maxSessionsPreventsLogin(false) // 동시 로그인 차단, false : 기존 세션 만료(default)
//                .invalidSessionUrl("/invalid") // 세션이 유효하지 않을 대 이동 할 페이지
                .expiredUrl("/expired"); // 세션이 만료된 경우 이동 할 페이지
        // 세션 고정 보호
        http.sessionManagement()
                .sessionFixation().changeSessionId(); // 기본 값 (서블릿 3.1 이상의 기본 값)

                // 새로운 세션 할당, 기존 세션의 모든 어트리뷰트가 새로운 세션으로 이동한다. (서블릿 3.1 이하의 기본 값)
//                .sessionFixation().migrateSession()

                // 새로운 세션 생성, 기존 세션의 모든 어트리뷰트는 새로운 세션으로 옮겨지지 않는다.
//                .sessionFixation().newSession() // 새로운 세션 생성

                // 설정해제, 공격에 방치된다.
//                .sessionFixation().none();
        // 세션 정책
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED); // 스프링 시큐리티가 필요 시 생성(기본 값)
//                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS) //  스프링 시큐리티가 항상 세션 생성
//                .sessionCreationPolicy(SessionCreationPolicy.NEVER) // 스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용
//                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 스프링 시큐리티가 생성하지도 않고 존재해도 사용하지 않음
    }
}
