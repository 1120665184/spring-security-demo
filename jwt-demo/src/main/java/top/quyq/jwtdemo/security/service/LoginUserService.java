package top.quyq.jwtdemo.security.service;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import top.quyq.jwtdemo.security.entity.User;

import java.util.ArrayList;
import java.util.List;

public class LoginUserService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //@TODO 设置虚假用户，此处应从数据库中获取数据信息
        User user = new User();
        user.setUsername(username);
        user.setPassword("admin");

        List<GrantedAuthority> authorities= new ArrayList<GrantedAuthority>(){
            {
                add(new SimpleGrantedAuthority("ROLE_ADMIN"));
            }
        };

        user.setAuthorities(authorities);
        return user;
    }
}
