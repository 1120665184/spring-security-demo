package top.quyq.common.security.permission;

import java.io.Serializable;

/**
 * 自定义权限路径
 */
public interface UrlBean extends Serializable {

    String getMethod();

    String getUrl();

    boolean supports(String Url , String method);

}
