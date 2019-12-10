package top.quyq.jwtdemo.security.handler;

import io.jsonwebtoken.Claims;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import top.quyq.common.constants.Constants;
import top.quyq.common.utils.JwtsUtils;
import top.quyq.jwtdemo.security.token.JwtAuthenticationToken;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

/**
 * JWT Token认证成功 处理器
 */
public class TokenAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        //获取token
        Claims token = ((JwtAuthenticationToken) authentication).getToken();

        if(this.shouldTokenRefresh(token.getIssuedAt())){
            String newToken = JwtsUtils.createJwtToken(authentication);
            //设置新token
            response.setHeader(Constants.Token.AUTHENTICATION_HEADER_NAME,newToken);
        }

    }

    /**
     * 检测是否改刷新token
     * @param issueAt
     * @return
     */
    protected boolean shouldTokenRefresh(Date issueAt){
        LocalDateTime issueTime = LocalDateTime.ofInstant(issueAt.toInstant(), ZoneId.systemDefault());
        return LocalDateTime.now().minusSeconds(Constants.Token.REFRESH_MILLIS / 1000).isAfter(issueTime);
    }

}
