package top.quyq.common.security.permission;

import java.util.Collection;
import java.util.Collections;
import java.util.Objects;
import java.util.stream.Collectors;

public class DefaultPermissionBean implements PermissionBean {

    private String owner;

    private Collection<UrlBean> urls;

    public DefaultPermissionBean setOwner(String owner) {
        this.owner = owner;
        return this;
    }

    public DefaultPermissionBean setUrls(Collection<UrlBean> urls) {
        this.urls = urls;
        return this;
    }

    @Override
    public String getOwner() {
        return this.owner;
    }

    @Override
    public Collection<? extends UrlBean> getUrls() {
        return this.urls;
    }

    @Override
    public Collection<? extends UrlBean> supportsReturn(String url, String method) {

        if(Objects.nonNull(this.urls) && this.urls.size() > 0){
            //返回匹配的url
          return  this.urls.stream()
                    .filter(u -> u.supports(url,method))
                    .collect(Collectors.toList());
        }

        return Collections.EMPTY_LIST;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DefaultPermissionBean that = (DefaultPermissionBean) o;
        return Objects.equals(owner, that.owner) &&
                Objects.equals(urls, that.urls);
    }

    @Override
    public int hashCode() {
        return Objects.hash(owner, urls);
    }
}
