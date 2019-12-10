package top.quyq.common.constants;

/**
 * 通用参数,静态变量公共接口
 */
public interface Constants {

    interface Token {
        /**
         * token存活时间
         */
        long ACTIVE_MILLIS = 10 * 60 * 1000 ;

        /**
         * token 刷新时间
         */
        long REFRESH_MILLIS = 5 * 60 * 1000 ;

        /**
         * 生成token私钥
         */
        String SIGNING_KEY = "top.quyq";
        /**
         * 请求头认证token信息
         */
        String AUTHENTICATION_HEADER_NAME = "Authorization";

    }

}
