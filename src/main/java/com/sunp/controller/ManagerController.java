package com.sunp.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping(value = "/manager")
public class ManagerController {

    @RequestMapping(value = "/getManagerInfo")
    @ResponseBody
    public String getManager(){
        return "manager info";
    }
}
