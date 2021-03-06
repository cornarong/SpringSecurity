package io.security.basicsecurity.security.configs;

import io.security.basicsecurity.security.common.FormAuthenticationDetailsSource;
import io.security.basicsecurity.security.handler.FormAccessDeniedHandler;
import io.security.basicsecurity.security.provider.FormAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
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
@EnableWebSecurity // ?????? ??????
@Order(1) // config ?????? ??????
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

//    @Autowired
//    private final UserDetailsService userDetailsService;
    @Autowired
    private FormAuthenticationDetailsSource authenticationDetailsSource;
    @Autowired
    private AuthenticationSuccessHandler formAuthenticationSuccessHandler;
    @Autowired
    private AuthenticationFailureHandler formAuthenticationFailureHandler;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(userDetailsService);
        // ?????? ?????? FormAuthenticationProvider??? ???????????? ?????? ????????? ?????? ??????.
        auth.authenticationProvider(authenticationProvider());
    }

    //  ?????? ?????? ?????? (WebIgnore ??????)
    // StaticResourceLocation ??????????????? ???????????? css,js,images ?????? ?????? ?????? ???????????? ????????? ???????????? "??????????????? ????????? ??????" ??????????????? ?????????.
    // ?????? ????????? ??????.permitAll()?????? ?????? ????????????? -> ????????????. ????????? permitAll()??? "??????????????? ????????? ?????????"??? ????????? ??????.
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .antMatchers("/favicon.ico", "/resources/**", "/error")
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // ?????? ??????
        http
                .authorizeRequests()
                .antMatchers("/", "/users", "user/login/**", "/login*").permitAll()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()
        // ?????? ??????
        .and()
                .formLogin() // formLogin??????
                    .loginPage("/login") // ????????? ?????????
                    .usernameParameter("username") // form??? id ???????????????
                    .passwordParameter("password") // form??? password ???????????????
                    .loginProcessingUrl("/login_proc") // form??? action ??????
                    .defaultSuccessUrl("/") // ????????? ????????? url
//                    .failureUrl("/login") // ????????? ????????? url
                    .authenticationDetailsSource(authenticationDetailsSource) // ?????? ?????? ??????
                    .successHandler(formAuthenticationSuccessHandler) // 1. ????????? custom success ???????????? ????????????.
//                    .successHandler(new AuthenticationSuccessHandler() { // 2. ????????? success ???????????? ????????????. ????????? ???????????????
//                        // ????????? ????????? authentication ????????? ??????????????? -
//                        @Override
//                        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                            RequestCache requestCache = new HttpSessionRequestCache();
//                            SavedRequest savedRequest = requestCache.getRequest(request, response); // savedRequest ?????? ???????????? ????????? ?????? ????????? ?????? ??????.
//                            String redirectUrl = savedRequest.getRedirectUrl();
//
//                            System.out.println("authentication : " + authentication.getName());
//                            // ????????? ???????????? ????????? ???????????? ?????? ?????? ??????(????????? ?????? ??????)??? ???????????? ?????? ?????????.
//                            response.sendRedirect(redirectUrl);
//                        }
//                    })
                    .failureHandler(formAuthenticationFailureHandler) // 1. ????????? custom failure ???????????? ????????????.
//                    .failureHandler(new AuthenticationFailureHandler() { // 2. ????????? fail ???????????? ????????????. ????????? ???????????????
//                        // ????????? ????????? exception ????????? ??????????????? -
//                        @Override
//                        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                            System.out.println("exception : " + exception.getMessage());
//                            response.sendRedirect("/loginPage");
//                        }
//                    });
                    .permitAll()
        .and()
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler());


        http
                .logout()
                    .logoutUrl("/logout") // ??????????????? ??????????????? logout ????????? post ???????????? ???????????? ??????.
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
//                .rememberMe()
//                    .rememberMeParameter("remember")
//                    .tokenValiditySeconds(3600)
//                    .alwaysRemember(false)
//                    .userDetailsService(userDetailsService)
//                    .and()
                .sessionManagement()
                    .sessionFixation().changeSessionId() // ?????? ?????? ?????? ??????. ?????? ??? ??? ?????? ?????? ID??? ?????? ?????? ?????? ?????????????????? ????????? ???????????? ???????????? ????????????.
                    .maximumSessions(1)
                    // ?????? ?????? ??????
                    .maxSessionsPreventsLogin(false); // default : false -> ?????? ???????????? ???????????? ????????? ??????????????? ?????? ???????????? ??????????????? ????????? ????????????.
                    // ?????? ?????? ??????

        // ?????? ?????? ?????? -> ?????? ????????? ??? ?????? : https://cornarong.tistory.com/82
        http.sessionManagement()
                .maximumSessions(1) // ?????? ?????? ?????? ?????? ???, -1 : ????????? ????????? ?????? ??????
                .maxSessionsPreventsLogin(false) // ?????? ????????? ??????, false : ?????? ?????? ??????(default)
//                .invalidSessionUrl("/invalid") // ????????? ???????????? ?????? ??? ?????? ??? ?????????
                .expiredUrl("/expired"); // ????????? ????????? ?????? ?????? ??? ?????????
        // ?????? ?????? ??????
        http.sessionManagement()
                .sessionFixation().changeSessionId(); // ?????? ??? (????????? 3.1 ????????? ?????? ???)
                // ????????? ?????? ??????, ?????? ????????? ?????? ?????????????????? ????????? ???????????? ????????????. (????????? 3.1 ????????? ?????? ???)
//                .sessionFixation().migrateSession()
                // ????????? ?????? ??????, ?????? ????????? ?????? ?????????????????? ????????? ???????????? ???????????? ?????????.
//                .sessionFixation().newSession() // ????????? ?????? ??????
                // ????????????, ????????? ????????????.
//                .sessionFixation().none();
        // ?????? ??????
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED); // ????????? ??????????????? ?????? ??? ??????(?????? ???)
//                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS) //  ????????? ??????????????? ?????? ?????? ??????
//                .sessionCreationPolicy(SessionCreationPolicy.NEVER) // ????????? ??????????????? ???????????? ????????? ?????? ???????????? ??????
//                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // ????????? ??????????????? ??????????????? ?????? ???????????? ???????????? ??????

/*        // ?????? ??????
        http
                .exceptionHandling()
                // ?????? ??????
                .authenticationEntryPoint(new AuthenticationEntryPoint() {
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        response.sendRedirect("/login"); // ????????? ?????? ?????? ????????????????????? ??????
                    }
                })
                // ?????? ??????
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/denied");
                    }
                });*/
    }

    // ?????? ?????? ?????? ??? ??????
    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        FormAccessDeniedHandler accessDeniedHandler = new FormAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");
        return accessDeniedHandler;
    }

    // ???????????? ?????????(passwordEncoder) ??? ??????
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new FormAuthenticationProvider(passwordEncoder());
    }

}
