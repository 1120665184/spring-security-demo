package top.quyq.jwtdemo.security.metadataSource;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @TODO
 * 从数据库或redis中加载权限
 */
public class TestAppMetadataSourceService implements AppMetadataSourceService {
    @Override
    public Map<String, String> getAllAppAuthorizationData() {
        return new LinkedHashMap<String,String >(){
            {
                put("/admin","ROLE_ADMIN");
            }
        };
    }

    @Override
    public Map<String, String> getAuthorizationByUrl(String url) {
        return new LinkedHashMap<String,String >(){
            {
                put("/admin","ROLE_ADMIN");
            }
        };
    }
}
