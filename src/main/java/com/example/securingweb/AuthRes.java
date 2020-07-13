package com.example.securingweb;

public class AuthRes {
	
	String userName;
	public AuthRes(String uname) {
		userName = uname;
	}
	public String getUserName() {
		return userName;
	}
	public void setUserName(String userName) {
		this.userName = userName;
	}

}
