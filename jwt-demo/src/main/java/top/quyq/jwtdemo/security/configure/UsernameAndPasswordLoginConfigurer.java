package top.quyq.jwtdemo.security.configure;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import top.quyq.jwtdemo.security.filter.UsernameAndPasswordLoginFilter;

/**
 * 组装配置 登陆filter
 * @param <T>
 * @param <B>
 */
public class UsernameAndPasswordLoginConfigurer<T extends UsernameAndPasswordLoginConfigurer<T,B>,
        B extends HttpSecurityBuilder<B>>
        extends AbstractHttpConfigurer<T,B> {

    private UsernameAndPasswordLoginFilter authFilter;


    public UsernameAndPasswordLoginConfigurer(String loginUrl){
        this.authFilter = new UsernameAndPasswordLoginFilter(loginUrl);
    }

    @Override
    public void configure(B http) throws Exception {
        //设置filter的AuthenticationManager
        authFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));

        //设置不将认证信息放入session中
        authFilter.setSessionAuthenticationStrategy(new NullAuthenticatedSessionStrategy());

        UsernameAndPasswordLoginFilter filter = postProcess(authFilter);

        http.addFilterAfter(filter, LogoutFilter.class);

    }

    //设置认证失败handler
    public UsernameAndPasswordLoginConfigurer<T,B> failureHandler(AuthenticationFailureHandler handler){
        authFilter.setAuthenticationFailureHandler(handler);
        return this;
    }

    //设置认证成功handler
    public UsernameAndPasswordLoginConfigurer<T,B> successHandler(AuthenticationSuccessHandler handler){
        authFilter.setAuthenticationSuccessHandler(handler);
        return this;
    }

}
