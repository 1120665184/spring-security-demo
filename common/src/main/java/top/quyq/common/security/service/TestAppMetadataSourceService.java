package top.quyq.common.security.service;

import top.quyq.common.security.permission.DefaultPermissionBean;
import top.quyq.common.security.permission.DefaultUrlBean;
import top.quyq.common.security.permission.PermissionBean;
import top.quyq.common.security.permission.UrlBean;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

/**
 * @TODO
 * 从数据库或redis中加载权限
 */
public class TestAppMetadataSourceService extends AppMetadataSourceService {

    @Override
    public Collection<PermissionBean> getAllAppAuthorizationData() {
        DefaultPermissionBean permission = new DefaultPermissionBean();
        permission.setOwner("ROLE_ADMIN");

        DefaultUrlBean url = new DefaultUrlBean();
        url.setUrl("/admin")
                .setMethod("*");

        permission.setUrls(Collections.singleton(url));

        return new ArrayList<PermissionBean>(){
            {
                add(permission);
            }
        };
    }
}
