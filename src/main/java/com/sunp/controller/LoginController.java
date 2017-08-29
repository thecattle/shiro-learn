package com.sunp.controller;

import com.sunp.service.LoginService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;


@Controller
@RequestMapping(value = "/sunp")
public class LoginController {

    private Logger logger = LoggerFactory.getLogger(LoginController.class);

    @Autowired
    private LoginService loginService;

    @RequestMapping(value = "/login", method = RequestMethod.GET, produces = "application/json; charset=utf-8")
    @ResponseBody
    public String login(String username, String password) {
        logger.info("sunp/login init");
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        token.setRememberMe(true);
        Subject currentUser = SecurityUtils.getSubject();
        try {
            currentUser.login(token);
        } catch (UnknownAccountException uae) {
            return "unknown account";
        } catch (IncorrectCredentialsException ice) {
            return "认证失败";
        } catch (LockedAccountException lae) {
            return "账户已锁定";
        } catch (ExcessiveAttemptsException eae) {
            return "登录失败次数过多";
        } catch (AuthenticationException ae) {
            return ae.getMessage();
        }
        return "login success";
    }

    @RequestMapping(value = "/loginOut", method = RequestMethod.GET, produces = "application/json; charset=utf-8")
    @ResponseBody
    public String loginOut() {
        Subject currentUser = SecurityUtils.getSubject();
        try {
            currentUser.logout();
        }catch (Exception e){
            logger.error("loginOut 异常",e);
            return "logout fail";
        }
        return "logout success";
    }

    @RequestMapping(value = "/getList", method = RequestMethod.GET)
    @ResponseBody
    public Map<String, Object> getList() {
        Map<String, Object> map = new HashMap<>();
        Subject currentUser = SecurityUtils.getSubject();

        map.put("isRemembered", currentUser.isRemembered() ? "session过期了，我是被记住的" : currentUser.isRemembered());
        map.put("isAuthenticated", currentUser.isAuthenticated() ? "session 还在，我是被认证的" : currentUser.isAuthenticated());


        //登录过，可以看到自己的名字
        //session 过期的时候，会触发当前判断，前提是登录过的用户设置了token.setRememberMe(true);
        if (currentUser.isRemembered()){
            map.put("name", "sunpeng");
        }
        //已认证，可以看到手机号
        if (currentUser.isAuthenticated()){
            map.put("phone", "xxxxx");
        }
        //未登录的情况下，只能看到其他信息
        map.put("weather", "sunny");

        return map;
    }
}
