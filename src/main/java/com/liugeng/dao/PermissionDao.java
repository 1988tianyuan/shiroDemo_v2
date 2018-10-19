package com.liugeng.dao;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;

import org.apache.shiro.crypto.SecureRandomNumberGenerator;

import com.liugeng.model.User;
import com.liugeng.utils.EncryptionUtil;

public class PermissionDao {

	public PermissionDao(){
		try {
			Class.forName("com.mysql.jdbc.Driver");
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
	}

	public Connection getConnection() throws SQLException{
		return DriverManager.getConnection("jdbc:mysql://127.0.0.1:3306/shirodemo?characterEncoding=UTF-8", "root",
			"123456");
	}

	public String getPassword(String userName){
		String sql = "select password from user where name = ?";
		try(Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sql)){
			ps.setString(1, userName);
			ResultSet result = ps.executeQuery();
			if (result.next()){
				return result.getString("password");
			}
		}catch (SQLException e){
			e.printStackTrace();
		}
		return null;
	}

	public Set<String> listRoles(String userName){
		Set<String> roles = new HashSet<>();
		String sql = "select role.name from user"
			+ " left join user_role on user.id = user_role.uid"
			+ " left join role on user_role.rid = role.id"
			+ " where user.name = ?";
		try(Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sql)){
			ps.setString(1, userName);
			ResultSet result = ps.executeQuery();
			while (result.next()){
				String name = result.getString("name");
				roles.add(name);
			}
		}catch (SQLException e){
			e.printStackTrace();
		}
		return roles;
	}

	public Set<String> listPermissions(String userName){
		Set<String> permissions = new HashSet<>();
		String sql = "select p.name from user"
			+ " left join user_role on user.id = user_role.uid"
			+ " left join role_permission rp on rp.rid = user_role.rid"
			+ " left join permission p on rp.pid = p.id"
			+ " where user.name = ?";
		try(Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sql)){
			ps.setString(1, userName);
			ResultSet result = ps.executeQuery();
			while (result.next()){
				String name = result.getString("name");
				permissions.add(name);
			}
		}catch (SQLException e){
			e.printStackTrace();
		}
		return permissions;

	}


	public boolean createUser(User user){
		String sql = "insert into user values (null, ?, ?, ?)";
		String salt = new SecureRandomNumberGenerator().nextBytes().toString();
		String pswdAfterEncryption = EncryptionUtil.strEncryptionByMd5(user.getPassword(), salt);

		user.setPassword(pswdAfterEncryption);
		user.setSalt(salt);

		try(Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sql)){
			ps.setString(1, user.getName());
			ps.setString(2, user.getPassword());
			ps.setString(3, user.getSalt());
			int success = ps.executeUpdate();
			return success > 0;
		}catch (SQLException e){
			e.printStackTrace();
		}
		return false;
	}

	public User getUser(String userName){
		String sql = "select name,password,salt from user where name = ?";
		try(Connection c = getConnection(); PreparedStatement ps = c.prepareStatement(sql)){
			ps.setString(1, userName);
			ResultSet resultSet = ps.executeQuery();
			User user = new User();
			if(resultSet.next()){
				String name = resultSet.getString("name");
				String password = resultSet.getString("password");
				String salt = resultSet.getString("salt");

				user.setName(name);
				user.setPassword(password);
				user.setSalt(salt);
			}
			return user;
		}catch (SQLException e){
			e.printStackTrace();
		}
		return null;
	}

	public static void main(String[] args){
		System.out.println(new PermissionDao().listRoles("liugeng"));
		System.out.println(new PermissionDao().listRoles("lilin"));
		System.out.println(new PermissionDao().listPermissions("liugeng"));
		System.out.println(new PermissionDao().listPermissions("lilin"));
	}





}
