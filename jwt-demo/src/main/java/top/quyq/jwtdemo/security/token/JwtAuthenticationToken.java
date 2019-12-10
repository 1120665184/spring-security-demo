package top.quyq.jwtdemo.security.token;

import io.jsonwebtoken.Claims;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private Claims tokenClaims;

    public JwtAuthenticationToken(Claims tokenClaims) {
        super(null);
        this.tokenClaims = tokenClaims;
    }

    public JwtAuthenticationToken(Claims tokenClaims, Collection<? extends GrantedAuthority> authorities){
        super(authorities);
        this.tokenClaims = tokenClaims;
        this.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return tokenClaims.getSubject();
    }

    public Claims getToken(){
        return tokenClaims;
    }
}
