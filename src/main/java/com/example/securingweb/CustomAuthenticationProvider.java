package com.example.securingweb;

import java.util.Collections;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String username = authentication.getName();
		String password = authentication.getCredentials().toString();
		System.out.println("User name :     " + username);
		System.out.println("User Password :    " + password);
		
	//	authentication.get
		if(password.contains(" "))
			System.out.println("Contains whitespace");

		password = AesUtil.getDcrypt(password.replaceAll(" ", "+"), username);

		System.out.println("password :  " + password);

		if ((username.equals("nvn") && password.equals("nvnpass"))
				|| (username.equals("p2ptestuser1") && password.equals("Welcome1")))
			return new UsernamePasswordAuthenticationToken(username, password, Collections.emptyList());
		else
			return null;

	}

	@Override
	public boolean supports(Class<?> aClass) {
		return aClass.equals(UsernamePasswordAuthenticationToken.class);
	}
}