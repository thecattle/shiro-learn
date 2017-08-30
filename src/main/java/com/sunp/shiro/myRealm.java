package com.sunp.shiro;

import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

public class myRealm extends AuthorizingRealm {
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {

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

        String jdbcAccountSalt="b93e50d8389262747e5b3d239b7fb6c8";
        String jdbcAccountName="sunpeng";
        String jdbcAccountPassword="39fd24859dc62d90e51e9a6a27fda3eb";//sunpeng

        if(jdbcAccountName.equals(token.getUsername())){

            /*
            通过HashedCredentialsMatcher类中的doCredentialsMatch进行认证
            根据 token 里的值  和  构造的 authcInfo 的值进行比对
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

    private void credent(String password){
//        RandomNumberGenerator rng = new SecureRandomNumberGenerator();
//        Object salt = rng.nextBytes().toBase64();
//        String hashedPasswordBase64 = new Sha256Hash(password, salt, 1024).toBase64();
//        return hashedPasswordBase64;

        String salt2 = new SecureRandomNumberGenerator().nextBytes().toHex();
        int hashIterations = 1024;
        SimpleHash hash = new SimpleHash("MD5", password, salt2, hashIterations);
        String encodedPassword = hash.toHex();
        System.out.println(encodedPassword);
        System.out.println(salt2);
    }

    public static void main(String[] args) {
        myRealm myRealm=new myRealm();
        myRealm.credent("sunpeng");
    }
}
