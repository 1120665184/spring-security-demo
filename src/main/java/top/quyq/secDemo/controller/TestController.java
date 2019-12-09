package top.quyq.secDemo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("hello")
    public String hello(){
        return "hello jwt";
    }

    @GetMapping("admin")
    public String admin(){
        return "hello admin";
    }

}
