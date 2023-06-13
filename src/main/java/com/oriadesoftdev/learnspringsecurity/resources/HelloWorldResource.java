package com.oriadesoftdev.learnspringsecurity.resources;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class HelloWorldResource {

    @GetMapping("/hello-world")
    public String helloWorld(){
        return "Hello World v1";
    }
}
