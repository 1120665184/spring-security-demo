package top.quyq.jwtdemo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import top.quyq.common.entity.Result;

@RestController

public class TestController {


    @GetMapping("/view/hello")
    public Result hello(){
        return Result.success("nihao");
    }

    @GetMapping("admin")
    public Result admin(){
        return Result.error("admin");
    }

}
