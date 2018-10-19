package com.liugeng.utils;

import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.SimpleHash;

public class EncryptionUtil {

	public static String strEncryptionByMd5(String str, String salt){
		String algorithm = "md5";
		int times = 2;
		return new SimpleHash(algorithm, str, salt, times).toString();
	}

}
