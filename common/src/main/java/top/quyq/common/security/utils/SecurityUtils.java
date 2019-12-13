package top.quyq.common.security.utils;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * security 自定义工具类
 */
public final class SecurityUtils {

     final static String URL_SPLIT_SYMBOL = " ";

    /**
     * 将字符串路径生成RequestMatcher
     * 路径类型为：method-url  例：post-/**
     * @param urls
     * @return
     */
    public static AntPathRequestMatcher[] createMatcher(List<String> urls,String splitSymbol){
        if(Objects.nonNull(urls)){
            List<AntPathRequestMatcher> ants = urls.stream().map(u -> {
                String[] methodAndUrl = u.split(splitSymbol);
                String method = null;
                String url ;
                if (methodAndUrl.length < 2) {
                    url = u;
                } else {
                    method = methodAndUrl[0].toUpperCase();
                    url = methodAndUrl[1];
                }
                return new AntPathRequestMatcher(url, method);
            }).collect(Collectors.toList());
            return ants.toArray(new AntPathRequestMatcher[ants.size()]);
        }
        return null;
    }

    public static AntPathRequestMatcher[] createMatcher(List<String> urls){
        return createMatcher(urls,URL_SPLIT_SYMBOL);
    }
}
