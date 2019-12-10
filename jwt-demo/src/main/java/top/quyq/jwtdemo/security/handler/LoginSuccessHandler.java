package top.quyq.jwtdemo.security.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import top.quyq.common.constants.Constants;
import top.quyq.common.entity.Result;
import top.quyq.common.entity.ResultCode;
import top.quyq.common.utils.JsonUtils;
import top.quyq.common.utils.JwtsUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * 登陆成功处理器
 */
public class LoginSuccessHandler implements AuthenticationSuccessHandler {


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        response.setContentType("application/json;charset=utf-8");
        Result result = Result.create()
                .setResultCode(ResultCode.CODE_SUCCESS_LOGIN)
                .build();
        //头部设置Token
        String jwtToken = JwtsUtils.createJwtToken(authentication);
        response.setHeader(Constants.Token.AUTHENTICATION_HEADER_NAME,jwtToken);
        //@TODO 此处可将token存储在数据库或redis中,用来判断账号是否退出

        PrintWriter out = response.getWriter();
        out.write(JsonUtils.getNonFilterObjectMapperInstance().writeValueAsString(result));
        out.flush();
        out.close();
    }
}
