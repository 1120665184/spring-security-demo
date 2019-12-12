package top.quyq.jwtdemo.security.metadataSource;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.util.AntPathMatcher;
import top.quyq.common.security.permission.PermissionBean;
import top.quyq.common.security.permission.UrlBean;
import top.quyq.common.security.service.AppMetadataSourceService;

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
        String method = fi.getHttpRequest().getMethod();
        Set<ConfigAttribute> setConfig = new LinkedHashSet<>();

        Map<UrlBean, String> authorizationByUrl = service.getAuthorizationByUrl(url,method);

        if(Objects.nonNull(authorizationByUrl)){
            authorizationByUrl.forEach((k,v) ->{
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

        Set<ConfigAttribute> setConfig = new LinkedHashSet<>();
        Collection<PermissionBean> allPermission = service.getAllAppAuthorizationData();

        String[] rolesAll = allPermission.stream().map(PermissionBean::getOwner)
                .toArray(String[]::new);

        setConfig.addAll(SecurityConfig.createList(rolesAll));

        setConfig.addAll(baseMetadataSource.getAllConfigAttributes());

        return setConfig;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }
}
