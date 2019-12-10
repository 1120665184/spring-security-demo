package top.quyq.jwtdemo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.Header;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import top.quyq.common.constants.Constants;
import top.quyq.jwtdemo.security.configure.TokenAuthenticationConfigurer;
import top.quyq.jwtdemo.security.configure.UsernameAndPasswordLoginConfigurer;
import top.quyq.jwtdemo.security.filter.TokenAuthenticationFilter;
import top.quyq.jwtdemo.security.filter.OptionsRequestFilter;
import top.quyq.jwtdemo.security.handler.*;
import top.quyq.jwtdemo.security.provider.TokenAuthenticationProvider;
import top.quyq.jwtdemo.security.service.LoginUserService;

import java.util.Arrays;

@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(tokenAuthenticationProvider())
                .authenticationProvider(daoAuthenticationProvider());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic().authenticationEntryPoint(authenticationEntryPoint())
                .and()
                .authorizeRequests()
                .antMatchers("/hello").authenticated()
                .antMatchers("/admin").hasRole("ADMIN")
                .antMatchers(HttpMethod.POST,"/login").permitAll()
                .anyRequest().authenticated()
                .and()
                //添加登录filter
                .apply(new UsernameAndPasswordLoginConfigurer<>("/login"))
                .successHandler(loginSuccessHandler())
                .failureHandler(loginFailureHandler())
                .and()
                //添加token filter
                .apply(new TokenAuthenticationConfigurer<>())
                .successHandler(tokenAuthenticationHandler())
                .failureHandler(loginFailureHandler())
                .and()
                .csrf().disable()
                .sessionManagement().disable()
                .formLogin().disable()
                .cors()  //支持跨域
                .and()
                .headers().addHeaderWriter(new StaticHeadersWriter(Arrays.asList(
                new Header("Access-control-Allow-Origin","*"),
                new Header("Access-Control-Expose-Headers",Constants.Token.AUTHENTICATION_HEADER_NAME))))
                .and()
                .addFilterAfter(new OptionsRequestFilter(), CorsFilter.class);
        http.exceptionHandling().accessDeniedHandler(tokenAccessDeniedHandler());
    }

    @Bean
    protected CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("GET","POST","HEAD", "OPTION"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.addExposedHeader(Constants.Token.AUTHENTICATION_HEADER_NAME);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean("tokenAuthenticationProvider")
    protected AuthenticationProvider tokenAuthenticationProvider() throws Exception {
        TokenAuthenticationProvider provider = new TokenAuthenticationProvider(loginUserDetailsService());
        return provider;
    }

    @Bean("daoAuthenticationProvider")
    protected AuthenticationProvider daoAuthenticationProvider() throws Exception {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(loginUserDetailsService());
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    protected UserDetailsService loginUserDetailsService(){
        return new LoginUserService();
    }

    @Bean("loginAuthenticationSuccessHandler")
    public AuthenticationSuccessHandler loginSuccessHandler(){
        return new LoginSuccessHandler();
    }

    @Bean("tokenAuthenticationSuccessHandler")
    public AuthenticationSuccessHandler tokenAuthenticationHandler(){
        return new TokenAuthenticationSuccessHandler();
    }

    @Bean
    public AuthenticationFailureHandler loginFailureHandler(){
        return new LoginFailureHandler();
    }

    @Bean
    public AccessDeniedHandler tokenAccessDeniedHandler(){
        return new TokenAccessDeniedHandler();
    }

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint(){
        return new NotLoginAuthenticationEntryPoint();
    }

}
