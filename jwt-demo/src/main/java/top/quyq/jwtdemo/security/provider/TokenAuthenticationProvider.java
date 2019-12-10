package top.quyq.jwtdemo.security.provider;

import io.jsonwebtoken.Claims;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.www.NonceExpiredException;
import org.springframework.security.web.context.support.SecurityWebApplicationContextUtils;
import top.quyq.common.constants.Constants;
import top.quyq.jwtdemo.security.entity.User;
import top.quyq.jwtdemo.security.service.LoginUserService;
import top.quyq.jwtdemo.security.token.JwtAuthenticationToken;

import java.util.Calendar;
import java.util.List;

/**
 * token 认证 提供者
 */
public class TokenAuthenticationProvider implements AuthenticationProvider {

    private UserDetailsService userService;

    public TokenAuthenticationProvider(UserDetailsService userService){
        this.userService = userService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Claims token = ((JwtAuthenticationToken) authentication).getToken();

        if(token.getExpiration().before(Calendar.getInstance().getTime()))
            throw new NonceExpiredException("Token 已过期");

        User user = (User) userService.loadUserByUsername(token.getSubject());

        if(user == null || user.getPassword()==null)
            throw new NonceExpiredException("Token 已过期");

        List<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList((String) token.get("authorities"));
        JwtAuthenticationToken Token = new JwtAuthenticationToken(token, authorities);

        return Token;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(JwtAuthenticationToken.class);
    }
}
