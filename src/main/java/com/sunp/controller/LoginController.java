package com.sunp.controller;

import com.sunp.service.LoginService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;


@Controller
@RequestMapping(value = "/sunp")
public class LoginController {

    private Logger logger= LoggerFactory.getLogger(LoginController.class);

    @Autowired
    private LoginService loginService;

    @RequestMapping(value = "/login",method = RequestMethod.GET)
    @ResponseBody
    public String login(String username, String password){
        logger.info("sunp/login init");
//        String username="sunpeng";
//        String password="password";

        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        token.setRememberMe(true);

        Subject currentUser = SecurityUtils.getSubject();
        currentUser.login(token);

        return "fail";
    }
}
