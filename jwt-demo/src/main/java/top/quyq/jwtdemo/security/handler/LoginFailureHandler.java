package top.quyq.jwtdemo.security.handler;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import top.quyq.common.entity.Result;
import top.quyq.common.entity.ResultCode;
import top.quyq.common.utils.JsonUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * 登陆失败处理器
 */
public class LoginFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        response.setContentType("application/json;charset=utf-8");
        Result result = Result.create()
                .setResultCode(ResultCode.CODE_FAIL_LOGIN, exception.getMessage())
                .build();

        PrintWriter out = response.getWriter();
        out.write(JsonUtils.getNonFilterObjectMapperInstance().writeValueAsString(result));
        out.flush();
        out.close();

    }
}
