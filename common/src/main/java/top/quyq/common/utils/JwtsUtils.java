package top.quyq.common.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.StringUtils;
import top.quyq.common.constants.Constants;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * JWT工具类
 */
public final class JwtsUtils {
    private JwtsUtils(){}

    /**
     * 生成token
     * @param authentication
     * @return
     */
    public static String createJwtToken(Authentication authentication){
        //角色拼接
        StringBuilder sb = new StringBuilder();
        if(Objects.nonNull(authentication.getAuthorities())){
            for (GrantedAuthority authority : authentication.getAuthorities()){
                sb.append(authority.getAuthority()).append(",");
            }
        }
        //设置头部
        Map header = new HashMap<String,String>(){
            {
                put("alg","HS512");
                put("typ","JWT");
            }
        };

        String jwt = Jwts.builder()
                .setHeader(header)
                .claim("authorities",sb.toString())
                .setSubject(authentication.getName())
                .setExpiration(new Date(System.currentTimeMillis() + Constants.Token.ACTIVE_MILLIS))
                .signWith(SignatureAlgorithm.HS512, Constants.Token.SIGNING_KEY)
                .compact();
        return jwt;

    }

    /**
     * 解析token
     * @param token
     * @return
     */
    public static Claims verifyJwtToken(String token){
        return Jwts.parser()
                .setSigningKey(Constants.Token.SIGNING_KEY)
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * 返回当前用户名
     * @param token
     * @return
     */
    public static String getUserName(String token){
       return Jwts.parser()
                .setSigningKey(Constants.Token.SIGNING_KEY)
                .parseClaimsJws(token)
                .getBody().getSubject();
    }

    /**
     * 从请求头中获取Token
     * @param req
     * @return
     */
    public static String getJwtTokenFromRequest(HttpServletRequest req){
        String authInfo = req.getHeader(Constants.Token.AUTHENTICATION_HEADER_NAME);
        if(StringUtils.hasText(authInfo)){
            return authInfo.replace("Bearer", "").trim();
        }

        return "";
    }

}
