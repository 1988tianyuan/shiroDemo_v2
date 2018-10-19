package com.liugeng;

import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.SimpleHash;

import com.liugeng.utils.EncryptionUtil;

public class EncryptionTest {

	public static void main(String[] args){
		String password = "123";
		String salt = new SecureRandomNumberGenerator().nextBytes().toString();
		System.out.printf("原始密码是 %s , 运算出来的密文是：%s ",password, EncryptionUtil.strEncryptionByMd5(password, salt));
	}

}
