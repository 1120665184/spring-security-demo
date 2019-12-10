package top.quyq.jwtdemo.security.handler;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import top.quyq.common.entity.Result;
import top.quyq.common.entity.ResultCode;
import top.quyq.common.utils.JsonUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * 未认证调用执行器
 */
public class NotLoginAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.setContentType("application/json;charset=utf-8");
        PrintWriter out = response.getWriter();

        Result result = Result.create()
                .setResultCode(ResultCode.CODE_FAIL_SECURITY)
                .build();

        out.write(JsonUtils.getNonFilterObjectMapperInstance().writeValueAsString(result));
        out.flush();
        out.close();
    }
}
