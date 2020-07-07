package com.example.securingweb;

import java.util.Arrays;

import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable().cors().and().authorizeRequests().antMatchers("/","/authenticate","/logout").permitAll()
				.anyRequest().authenticated().and().formLogin().loginProcessingUrl("/authenticate")
				.successHandler((request, response, authenticate) -> {
					response.getOutputStream().println("{\"userName\" : \"" + request.getParameter("username") + "\"}");
					System.out.println("in there[[[");
				}).failureHandler((req, res, auth) -> {
					System.out.println(req.getParameter("username"));
					System.out.println(req.getParameter("password"));
				}).permitAll().and().logout().addLogoutHandler((req, res, auth) -> {
					System.out.println("in logout handeler");
					res.setStatus(HttpServletResponse.SC_OK);
				}).permitAll();
	}

	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication().withUser("nvn").password("{noop}nvnpass").roles("USER").and()
				.withUser("p2ptestuser1").password("{noop}Welcome1").roles("USER");
		// System.out.println("in [in[[[mernoniodf");
	}

	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList("http://localhost:8282", "http://localhost:8080"));
		configuration.setAllowedMethods(Arrays.asList("GET", "POST"));
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}
}
