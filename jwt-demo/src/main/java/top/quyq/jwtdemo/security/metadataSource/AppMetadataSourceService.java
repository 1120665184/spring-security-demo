package top.quyq.jwtdemo.security.metadataSource;

import java.util.Map;

public interface AppMetadataSourceService {

    /**
     * 获取所有权限数据
     * @return
     */
    Map<String,String> getAllAppAuthorizationData();

    /**
     * 查找以指定url开头的权限数据
     * @param url
     * @return
     */
    Map<String,String> getAuthorizationByUrl(String url);

}
