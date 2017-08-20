package com.sunp.service.impl;

import com.sunp.service.LoginService;
import org.springframework.stereotype.Service;

@Service
public class LoginServiceImpl implements LoginService {
    public boolean login(String name, String passWord) {
        return true;
    }
}
