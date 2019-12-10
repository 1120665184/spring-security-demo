package top.quyq.jwtdemo.security.filter;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;
import top.quyq.common.utils.JsonUtils;
import top.quyq.jwtdemo.security.entity.User;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class UsernameAndPasswordLoginFilter extends AbstractAuthenticationProcessingFilter {


    public UsernameAndPasswordLoginFilter(String defaultFilterProcessesUrl) {
        super(new AntPathRequestMatcher("/login", "POST"));
    }

    /**
     * 从请求中获取用户名，密码。并生成token
     * @param request
     * @param response
     * @return
     * @throws AuthenticationException
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        User user = null;

        try {
            user = JsonUtils.getNonFilterObjectMapperInstance()
                    .readValue(request.getInputStream(),User.class);
        }catch (Exception e){
            throw new BadCredentialsException("缺少必要参数");
        }

        if(!StringUtils.hasText(user.getUsername()) ||
                !StringUtils.hasText(user.getPassword())){
            throw new BadCredentialsException("缺少必要参数");
        }

        return getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword()));
    }

}
