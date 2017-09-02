package com.sunp.shiro;

import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class myRealm extends AuthorizingRealm {
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        String username =(String) super.getAvailablePrincipal(principalCollection);
        SimpleAuthorizationInfo info =new SimpleAuthorizationInfo();

        if ("sunpeng".equals(username)){
            List<String> roles=new ArrayList<>();
            roles.add("admin");
            List<String> permissions=new ArrayList<>();
            permissions.add("admin:list");
            info.addRoles(roles);
            info.addStringPermissions(permissions);
            return info;
        }

//        if ("sunpeng1".equals(username)){
//            List<String> roles=new ArrayList<>();
//            roles.add("manager");
//            List<String> permissions=new ArrayList<>();
//            permissions.add("manager:list");
//            info.addRoles(roles);
//            info.addStringPermissions(permissions);
//            return info;
//        }


        return null;
    }

    /**
     * 认证用户的操作
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        UsernamePasswordToken token = (UsernamePasswordToken)authenticationToken;
        System.out.print("验证当前Subject时获取到token：");
        System.out.println(ReflectionToStringBuilder.toString(token, ToStringStyle.MULTI_LINE_STYLE));

        //模拟数据库的用户信息
        String jdbcAccountSalt="nBJRREq/zFQl7aG5o4z0PA==";
        String jdbcAccountName="sunpeng";
        String jdbcAccountPassword="PQA/UP40yaw2+inRXewvSJG6Q7QYiuycbvUoFEil9Vs=";//sunpeng

        if(jdbcAccountName.equals(token.getUsername())){

            /*
            通过HashedCredentialsMatcher类中的doCredentialsMatch进行认证
            根据 token 里的值  和  构造的 authcInfo 的值进行比对.
            如果实现这个SaltedAuthenticationInfo接口的话，可以 get 到 salt，但是我觉得不好，不能把 salt 暴露出去
             */
            AuthenticationInfo authcInfo = new SimpleAuthenticationInfo(
                    jdbcAccountName,
                    jdbcAccountPassword,
                    ByteSource.Util.bytes(jdbcAccountSalt),
                    this.getName());
            return authcInfo;
        }
        if ("sunp".equals(token.getUsername())){
            throw new AuthenticationException("用户名少了三个字母啊兄弟");
        }

        return null;
    }


    /**
     * 模拟创建用户时候存入的密码和盐
     * @param password
     */
    private void credent(String password){

        //散列随机数
        String salt = new SecureRandomNumberGenerator().nextBytes().toBase64();
        //散列迭代次数
        int hashIterations=1024;

//       SimpleHash hash = new SimpleHash("SHA-256", password, salt, hashIterations);

        /*
        shiro.xml 中  storedCredentialsHexEncoded=true 则需要 .toHex()
        shiro.xml 中  storedCredentialsHexEncoded=false 则需要 .toBase64()
         */
        String encodedPassword = new Sha256Hash(password, salt, hashIterations).toBase64();
        System.out.println(encodedPassword);
        System.out.println(salt);
    }

    public static void main(String[] args) {
        myRealm myRealm=new myRealm();
        myRealm.credent("sunpeng");
    }
}
