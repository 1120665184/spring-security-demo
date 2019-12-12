package top.quyq.common.security.permission;

import java.io.Serializable;
import java.util.Collection;

/**
 * 自定义权限
 */
public interface PermissionBean extends Serializable {

    String getOwner();

    Collection<? extends UrlBean> getUrls();

    Collection<? extends UrlBean> supportsReturn(String url,String method);

}
