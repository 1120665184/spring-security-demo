package top.quyq.jwtdemo.security.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import top.quyq.common.entity.Result;
import top.quyq.common.entity.ResultCode;
import top.quyq.common.utils.JsonUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class TokenLogoutSuccessHandler implements LogoutSuccessHandler {

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        response.setContentType("application/json;charset=utf-8");

        PrintWriter out = response.getWriter();

        Result result = Result.create()
                .setResultCode(ResultCode.CODE_OK)
                .build();

        out.write(JsonUtils.getNonFilterObjectMapperInstance().writeValueAsString(result));
        out.flush();
        out.close();

    }
}
