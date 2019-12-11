package top.quyq.jwtdemo.security.metadataSource;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.util.AntPathMatcher;

import java.util.*;

public class AppFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {
    //系统默认配置source
    private FilterInvocationSecurityMetadataSource baseMetadataSource;
    private AppMetadataSourceService service;

    private final AntPathMatcher antPathMatcher = new AntPathMatcher();

    public AppFilterInvocationSecurityMetadataSource(
            FilterInvocationSecurityMetadataSource baseMetadataSource,
            AppMetadataSourceService service
    ){
        this.baseMetadataSource = baseMetadataSource;
        this.service = service;
    }

    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {

        FilterInvocation fi = (FilterInvocation) object;
        String url = fi.getRequestUrl();
        Set<ConfigAttribute> setConfig = new LinkedHashSet<>();

        Map<String, String> authorizationByUrl = service.getAuthorizationByUrl(url);

        if(Objects.nonNull(authorizationByUrl)){
            authorizationByUrl.forEach((k,v) ->{
                if(antPathMatcher.match(k,url))
                    setConfig.addAll(SecurityConfig.createListFromCommaDelimitedString(v));
            });
        }
        if(setConfig.size() == 0){
            setConfig.addAll(baseMetadataSource.getAttributes(object));
        }


        return setConfig;
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        Map<String, String> appRoles = service.getAllAppAuthorizationData();
        Set<ConfigAttribute> setConfig = new LinkedHashSet<>();


        appRoles.forEach((k,v) ->
                setConfig.addAll(SecurityConfig.createListFromCommaDelimitedString(v)));

        setConfig.addAll(baseMetadataSource.getAllConfigAttributes());

        return setConfig;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }
}
