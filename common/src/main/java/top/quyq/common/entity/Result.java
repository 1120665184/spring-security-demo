package top.quyq.common.entity;

import java.io.Serializable;
import java.util.Objects;

public class Result implements Serializable {

    private static final long serialVersionUID = 2657432395754169065L;
    private Integer code;

    private String msg;

    private Object data;

    private Result(){}

    static public Result success(){
        return Result.create()
                .setResultCode(ResultCode.CODE_OK)
                .build();
    }

    static public Result success(Object data){
        return Result.create()
                .setResultCode(ResultCode.CODE_OK)
                .setData(data)
                .build();
    }

    static public Result error(String msg){
        return Result.create()
                .setResultCode(ResultCode.CODE_FAIL_OTHER,msg)
                .build();
    }

    static public Result error(ResultCode resultCode){
        return Result.create()
                .setResultCode(resultCode)
                .build();
    }

    static public Result error(ResultCode resultCode,String msg){
        return Result.create()
                .setResultCode(resultCode,msg)
                .build();
    }

    static public ResultBuild create(){
        return new ResultBuild();
    }


    public static class ResultBuild {
        private Result result;

        public ResultBuild(){
            this.result = new Result();
        }

        public ResultBuild setCode(Integer code){
            this.result.code = code;
            return this;
        }

        public ResultBuild setMsg(String msg){
            this.result.msg = msg;
            return this;
        }

        public ResultBuild setData(Object data){
            this.result.data = data;
            return this;
        }

        public ResultBuild setResultCode(ResultCode code){
            this.result.code = code.getCode();
            this.result.msg = code.getMsg();
            return this;
        }

        public ResultBuild setResultCode(ResultCode code,String msg){
            this.result.code = code.getCode();
            this.result.msg = code.getMsg();
            if(Objects.nonNull(msg))
                this.result.msg = msg;
            return this;
        }


        public Result build(){
            return this.result;
        }


    }


    public Integer getCode() {
        return code;
    }

    public String getMsg() {
        return msg;
    }

    public Object getData() {
        return data;
    }
}
