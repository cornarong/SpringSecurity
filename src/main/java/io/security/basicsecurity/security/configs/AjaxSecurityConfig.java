package io.security.basicsecurity.security.configs;

import io.security.basicsecurity.security.common.AjaxLoginUrlAuthenticationEntryPoint;
import io.security.basicsecurity.security.filter.AjaxLoginProcessingFilter;
import io.security.basicsecurity.security.handler.AjaxAccessDeniedHandler;
import io.security.basicsecurity.security.handler.AjaxAuthenticationFailureHandler;
import io.security.basicsecurity.security.handler.AjaxAuthenticationSuccessHandler;
import io.security.basicsecurity.security.provider.AjaxAuthenticationProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@Order(0) // config 실행 순서
@Slf4j
public class AjaxSecurityConfig extends WebSecurityConfigurerAdapter {

    // 사용자 인증 시도 -> AjaxLoginProcessingFilter에서 인증처리에 관련된 내용을 인증객체(ID,PASSWORD등)로 생성
    // -> AuthenticationManager로 전달 -> AuthenticationManager은 AuthenticationProvider에게 인증처리를 위임
    // -> 인증을 거친 결과값(성공or실패)을 AjaxLoginProcessingFilter로 다시 전달 (인증필터가 최종결과값을 받는다)
    // -> AuthenticationSuccessHandler or AuthenticationFailureHandler을 호출한다.

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(ajaxAuthenticationProvider());
    }

    @Bean // 인증 처리
    public AuthenticationProvider ajaxAuthenticationProvider(){
        return new AjaxAuthenticationProvider();
    }

    @Bean // 인증 성공 핸들러
    public AuthenticationSuccessHandler ajaxAuthenticationSuccessHandler(){
        return new AjaxAuthenticationSuccessHandler();
    }

    @Bean // 인증 실패 핸들러
    public AuthenticationFailureHandler ajaxAuthenticationFailureHandler(){
        return new AjaxAuthenticationFailureHandler();
    }

    @Bean // 인증 거부 핸들러
    public AccessDeniedHandler ajaxAccessDeniedHandler() {
        return new AjaxAccessDeniedHandler();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .antMatcher("/api/**")
                .authorizeRequests()
                .antMatchers("/api/messages").hasRole("MANAGER") // 매니저 권한 사용자만 messages 에 접근 가능하오(TEST)
                .antMatchers("/api/login").permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class);

        http
                .exceptionHandling()
                .authenticationEntryPoint(new AjaxLoginUrlAuthenticationEntryPoint())
                .accessDeniedHandler(ajaxAccessDeniedHandler());

        // 사이트간 요청 위조 - CSRF (csrf설정은 기본적으로 활성화 되어있음 사용하지 않을 경우에만 선언해주면 된다.)
//        http.csrf().disable();

    }

    // 인증 필터 - AjaxAuthenticationFilter
    @Bean
    public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() throws Exception {
        AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
        ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManagerBean());
        // * 성공/실패 핸들러의 Form방식과 차이점 : Form방식은 성공 or 실패 시 리다이렉션으로 화면이동이 가능하지만
        // * Ajax방식은 단순 결과값을 JSON형식으로 BODY에 담아서 전달만 해주게 된다.
        ajaxLoginProcessingFilter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler()); // 인증 성공 시
        ajaxLoginProcessingFilter.setAuthenticationFailureHandler(ajaxAuthenticationFailureHandler()); // 인증 실패 시
        return ajaxLoginProcessingFilter;
    }
}
