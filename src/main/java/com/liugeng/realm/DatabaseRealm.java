package com.liugeng.realm;

import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import com.liugeng.dao.PermissionDao;
import com.liugeng.model.User;
import com.liugeng.utils.EncryptionUtil;

public class DatabaseRealm extends AuthorizingRealm {

	private static final PermissionDao dao = new PermissionDao();

	//权限验证
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
		String userName = (String) principalCollection.getPrimaryPrincipal();

		//从数据库中获取权限信息
		Set<String> permissions = dao.listPermissions(userName);
		Set<String> roles = dao.listRoles(userName);

		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();

		//填充权限信息
		info.setRoles(roles);
		info.setStringPermissions(permissions);

		return info;
	}

	//登录验证
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws
		AuthenticationException {
		UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;
		String userName = token.getPrincipal().toString();
		String password = new String(token.getPassword());
		User user = dao.getUser(userName);

		//进行登陆验证，验证出错则抛出异常
//		if(user != null){
//			String encryptionPswd = EncryptionUtil.strEncryptionByMd5(password, user.getSalt());
//			String pswdInDb = user.getPassword();
//			if(pswdInDb.equals(encryptionPswd)){
//				return new SimpleAuthenticationInfo(userName, password, getName());
//			}
//		}
//		throw new AuthenticationException();

		String pswdInDb = user.getPassword();
		String salt = user.getSalt();

		//无需自己判断，shiro帮我们判断了，需要在shiro.ini中配置HashedCredentialsMatcher
		return new SimpleAuthenticationInfo(userName, pswdInDb, ByteSource.Util.bytes(salt), getName());

	}
}
