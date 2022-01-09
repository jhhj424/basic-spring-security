package io.security.basicsecurity;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;

@Slf4j
@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS", "USER");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN", "SYS", "USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated()
        ;
        http
                .formLogin()
        ;

//        http
//                .authorizeRequests()
//                .anyRequest().authenticated();
//        http
//                .formLogin()
////                .loginPage("/loginPage")
//                .defaultSuccessUrl("/")
//                .failureUrl("/login")
//                .usernameParameter("userId")
//                .passwordParameter("passwd")
//                .loginProcessingUrl("/login_proc")
//                .successHandler((request, response, authentication) -> {
//                    log.info("authentication: {}", authentication.getName());
//                    response.sendRedirect("/");
//                })
//                .failureHandler((request, response, exception) -> {
//                    log.error("exception: {}", exception.getMessage());
//                    response.sendRedirect("/login");
//                })
//                .permitAll()
//        ;
//        http
//                .logout()
//                .logoutUrl("/logout")
//                .logoutSuccessUrl("/login")
//                .addLogoutHandler((request, response, authentication) -> {
//                    request.getSession().invalidate();
//                })
//                .logoutSuccessHandler((request, response, authentication) -> {
//                    response.sendRedirect("/login");
//                })
//        ;
//        http
//                .rememberMe()
//                .rememberMeParameter("remember")
//                .tokenValiditySeconds(3600)
//                .userDetailsService(userDetailsService)
//        ;
//        http
//                .sessionManagement()
//                .maximumSessions(1)
//                .maxSessionsPreventsLogin(true)
////                .expiredUrl("/expired")
//        ;
////        http
////                .sessionManagement()
////                .sessionFixation()
////                .changeSessionId() // 기본적으로 스프링 시큐리티가 설정해줌
////        ;
    }
}
