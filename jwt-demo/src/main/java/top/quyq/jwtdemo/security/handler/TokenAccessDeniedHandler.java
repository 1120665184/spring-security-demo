package top.quyq.jwtdemo.security.handler;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import top.quyq.common.entity.Result;
import top.quyq.common.entity.ResultCode;
import top.quyq.common.utils.JsonUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * 授权不通过调用执行器
 */
public class TokenAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        response.setContentType("application/json;charset=utf-8");
        PrintWriter out = response.getWriter();

        Result result = Result.create()
                .setResultCode(ResultCode.CODE_NO_SECURITY)
                .build();

        out.write(JsonUtils.getNonFilterObjectMapperInstance().writeValueAsString(result));
        out.flush();
        out.close();
    }
}
