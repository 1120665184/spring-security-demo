package top.quyq.common.entity;

public enum ResultCode {
    CODE_OK(200,"请求成功"),
    CODE_BUSY(-1,"系统繁忙，请稍后尝试"),
    CODE_FAIL(500,"请求出错"),
    CODE_FAIL_CAPTCHA(4000,"验证码不匹配"),
    CODE_FAIL_LOGIN(501,"登录失败"),
    CODE_FAIL_REGISTER(502, "注册失败"),
    CODE_FAIL_SECURITY(503, "操作需要先登录"),
    CODE_NO_SECURITY(504, "权限不足"),
    CODE_SUCCESS_LOGIN(201,"登陆成功"),

    CODE_FAIL_OTHER(555,"其他异常");


    private ResultCode(Integer code , String msg){
        this.code = code ;
        this.msg = msg ;
    }

    private Integer code;
    private String msg;

    public Integer getCode(){
        return this.code;
    }

    public String getMsg(){
        return this.msg;
    }


}
