package top.quyq.jwtdemo.security.configure;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import top.quyq.jwtdemo.security.filter.TokenAuthenticationFilter;

/**
 * 组装配置 token认证filter
 * @param <T>
 * @param <B>
 */
public class TokenAuthenticationConfigurer<T extends TokenAuthenticationConfigurer<T,B>,
        B extends HttpSecurityBuilder<B>>
        extends AbstractHttpConfigurer<T,B> {

    private TokenAuthenticationFilter authFilter;

    public TokenAuthenticationConfigurer(){

        this.authFilter = new TokenAuthenticationFilter();
    }

    @Override
    public void configure(B http) throws Exception {
        //设置manager
        authFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
        authFilter.setTrustResolver(http.getSharedObject(AuthenticationTrustResolver.class));
        //将该过滤器添加到LogoutFilter之前
        TokenAuthenticationFilter filter = postProcess(authFilter);
        http.addFilterBefore(filter, LogoutFilter.class);
    }

    //设置匿名用户可访问url
    public TokenAuthenticationConfigurer<T, B> permissiveRequestUrls(String ... urls){
        authFilter.setPermissiveRequestMatchers(urls);
        return this;
    }

    //设置验证失败 处理器
    public TokenAuthenticationConfigurer<T,B> failureHandler(AuthenticationFailureHandler handler){
        authFilter.setFailureHandler(handler);
        return this;
    }
    //设置验证成功 处理器
    public TokenAuthenticationConfigurer<T,B> successHandler(AuthenticationSuccessHandler handler){
        authFilter.setSuccessHandler(handler);
        return this;
    }

}
