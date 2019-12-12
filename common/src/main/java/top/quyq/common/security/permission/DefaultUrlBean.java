package top.quyq.common.security.permission;

import org.springframework.util.AntPathMatcher;

import java.util.Objects;

public class DefaultUrlBean implements UrlBean {

    private String method;

    private String url;

    private AntPathMatcher antPathMatcher = new AntPathMatcher();

    public DefaultUrlBean setMethod(String method) {
        this.method = method;
        return this;
    }

    public DefaultUrlBean setUrl(String url) {
        this.url = url;
        return this;
    }

    @Override
    public String getMethod() {
        return this.method;
    }

    @Override
    public String getUrl() {
        return this.url;
    }

    @Override
    public boolean supports(String Url, String method) {
        boolean res = false;
        if("*".equals(this.method) || method.equalsIgnoreCase(this.method)){
            res = true;
        }
        if(res){
           res = antPathMatcher.match(this.url,Url) ;
        }
        return res;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DefaultUrlBean that = (DefaultUrlBean) o;
        return Objects.equals(method, that.method) &&
                Objects.equals(url, that.url);
    }

    @Override
    public int hashCode() {
        return Objects.hash(method, url);
    }
}
