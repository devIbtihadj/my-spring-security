package com.ibtihadj.security.controllers;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static com.ibtihadj.security.utils.constants.JavaConstant.API_BASE_URL;

@RestController
@RequestMapping(API_BASE_URL)
@CrossOrigin("*")
public class SecureController {

    @GetMapping("test")
    public void test(){
        System.out.println("Secure path");
    }
}
