package top.quyq.common.security.service;

import top.quyq.common.security.permission.PermissionBean;
import top.quyq.common.security.permission.UrlBean;

import java.util.*;

public abstract class AppMetadataSourceService {

    /**
     * 获取所有权限数据
     * @return
     */
    public abstract Collection<PermissionBean> getAllAppAuthorizationData();

    /**
     * 查找以指定url开头的权限数据
     * @param url
     * @param method
     * @return
     */
    public Map<UrlBean,String> getAuthorizationByUrl(String url, String method){
        //获取所有的权限
        Collection<PermissionBean> allPermission = this.getAllAppAuthorizationData();

        //匹配指定路径和url的权限并返回数据
        if(Objects.nonNull(allPermission) && allPermission.size() > 0){
            Map<UrlBean,String> permissionMap = new HashMap<>();

            allPermission.forEach(v -> {
                Collection<? extends UrlBean> urlBeans = v.supportsReturn(url, method);

                if(Objects.nonNull(urlBeans) && urlBeans.size() > 0 ){
                    urlBeans.forEach(urlBean ->{

                        String roles = permissionMap.get(urlBean);
                        if(Objects.isNull(roles)){
                            permissionMap.put(urlBean,v.getOwner());
                        }else {
                            permissionMap.put(urlBean,roles + "," + v.getOwner());
                        }

                    });
                }
            });
            return permissionMap;
        }

        return Collections.EMPTY_MAP;
    }

}
