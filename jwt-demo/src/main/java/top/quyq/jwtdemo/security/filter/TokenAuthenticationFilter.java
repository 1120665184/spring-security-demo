package top.quyq.jwtdemo.security.filter;

import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import top.quyq.common.constants.Constants;
import top.quyq.common.utils.JwtsUtils;
import top.quyq.jwtdemo.security.token.JwtAuthenticationToken;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * 从 authorization  字段中获取 token，生成 JwtAuthenticationToken
 */

public class TokenAuthenticationFilter extends OncePerRequestFilter {


    private AuthenticationManager authenticationManager;

    private AuthenticationSuccessHandler successHandler ;
    private AuthenticationFailureHandler failureHandler ;
    private List<RequestMatcher> permissiveRequestMatchers ;

    private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

    private RequestHeaderRequestMatcher requestHeaderRequestMatcher;

    public TokenAuthenticationFilter(){

        this.requestHeaderRequestMatcher = new RequestHeaderRequestMatcher(Constants.Token.AUTHENTICATION_HEADER_NAME);
    }


    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {

        //将没有带Token的请求信息放过  如果为指定跳过的路径，则跳过
        if(!this.requestHeaderRequestMatcher.matches(req) || permissiveRequest(req)){
            SecurityContextHolder.clearContext();
            chain.doFilter(req,response);
            return;
        }

        //将已经通过认证的信息放过
       /* Authentication authentication = SecurityContextHolder.getContext()
                .getAuthentication();
        if(Objects.nonNull(authentication)){
            chain.doFilter(req,response);
            return;
        }*/

        Authentication authenInfo = null;
        AuthenticationException faild = null;

        try {

            String Token = JwtsUtils.getJwtTokenFromRequest(req);
            if(StringUtils.hasText(Token)){
                //生成Token
                JwtAuthenticationToken authToken = new JwtAuthenticationToken(JwtsUtils.verifyJwtToken(Token));
                authenInfo = this.getAuthenticationManager().authenticate(authToken);
            }else {
                faild = new InsufficientAuthenticationException("Token 不能为空");
            }

        }
        catch (ExpiredJwtException e){
            faild = new BadCredentialsException("Token 已超时");
        }
        catch (AuthenticationException e){
          faild = e;
        } catch (Exception e){
            System.out.println(e);
            faild = new InternalAuthenticationServiceException("Token 解析错误");
        }

        if(Objects.nonNull(authenInfo)  && faild == null){
            successfulAuthentication(req,response,chain,authenInfo);
        } else if(!permissiveRequest(req)){
            unsuccessfulAuthentication(req,response,faild);
            return;
        }

        chain.doFilter(req,response);
    }

    /**
     * 认证成功回调
     * @param request
     * @param response
     * @param chain
     * @param authResult
     * @throws IOException
     * @throws ServletException
     */
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response, FilterChain chain,
                                            Authentication authResult)
            throws IOException, ServletException{

        SecurityContextHolder.getContext().setAuthentication(authResult);
        if(Objects.nonNull(successHandler)){
            successHandler.onAuthenticationSuccess(request,response,authResult);
        }

    }

    /**
     * 认证不通过回调
     * @param request
     * @param response
     * @param failed
     * @throws IOException
     * @throws ServletException
     */
    protected void unsuccessfulAuthentication(HttpServletRequest request,
                                              HttpServletResponse response, AuthenticationException failed)
            throws IOException, ServletException {

        SecurityContextHolder.clearContext();

        if(Objects.nonNull(failureHandler)){
            failureHandler.onAuthenticationFailure(request,response,failed);
        }

    }


    /**
     *  验证是否为指定跳过的路径
     * @param request
     * @return
     */
    protected boolean permissiveRequest(HttpServletRequest request) {
        if(permissiveRequestMatchers == null)
            return false;
        for(RequestMatcher permissiveMatcher : permissiveRequestMatchers) {
            if(permissiveMatcher.matches(request))
                return true;
        }
        return false;
    }


    public AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }

    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    public AuthenticationSuccessHandler getSuccessHandler() {
        return successHandler;
    }

    public void setSuccessHandler(AuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
    }

    public AuthenticationFailureHandler getFailureHandler() {
        return failureHandler;
    }

    public void setFailureHandler(AuthenticationFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
    }

    public List<RequestMatcher> getPermissiveRequestMatchers() {
        return permissiveRequestMatchers;
    }

    public void setPermissiveRequestMatchers(String[] urls) {
        if(Objects.isNull(urls))    return;
        ArrayList<RequestMatcher> objects = new ArrayList<>();
        for(String url : urls){
            objects.add(new AntPathRequestMatcher(url));
        }
        this.permissiveRequestMatchers = objects;
    }

    public AuthenticationTrustResolver getTrustResolver() {
        return trustResolver;
    }

    public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
        this.trustResolver = trustResolver;
    }
}
