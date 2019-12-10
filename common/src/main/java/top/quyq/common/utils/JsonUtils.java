package top.quyq.common.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

/**\
 * JSON操作通用類
 */
public final class JsonUtils {

    protected final static ObjectMapper mapper;

    static {
        mapper = new ObjectMapper();

        //禁用默认转换成时间毫秒值的方式，启用ISO8601标准格式化为字符串
        mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        //添加对JSR310的日期时间模式的支持
        mapper.registerModule(new JavaTimeModule());
    }

    private JsonUtils(){}

    public static ObjectMapper getNonFilterObjectMapperInstance(){return mapper;}

}
