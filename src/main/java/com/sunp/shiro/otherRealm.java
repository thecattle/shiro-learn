package com.sunp.shiro;

import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

public class otherRealm extends AuthorizingRealm{
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        return null;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        UsernamePasswordToken token = (UsernamePasswordToken)authenticationToken;
        System.out.print("otherRealm 验证当前Subject时获取到token：");
        System.out.println(ReflectionToStringBuilder.toString(token, ToStringStyle.MULTI_LINE_STYLE));

        if("sunpeng1".equals(token.getUsername())){
            AuthenticationInfo authcInfo = new SimpleAuthenticationInfo("sunpeng1", "password", this.getName());
            return authcInfo;
        }
        if ("sunp1".equals(token.getUsername())){
            throw new AuthenticationException("用户名少了三个字母啊兄弟2");
        }
        return null;
    }
}