package top.quyq.common.security.entity;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;

@ConfigurationProperties(prefix = "spring.security")
@Data
public class SecurityConfigureBean {

    /**
     * 路径和method分割标识
     */
    private String methodUrlSplitSymbol = " ";

    /**
     * 跳过认证的路径
     */
    private List<String> permitUrls = Collections.EMPTY_LIST;
    /**
     * 允许匿名访问的路径
     */
    private List<String> anonymousUrls = Collections.EMPTY_LIST;

}
