package com.in28minutes.learnspringsecurity.basic;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

// @EnableMethodSecurity will allow pre and post notations such as
// @PreAuthorize("hasRole('USER') and #username == authentication.name") on mapping methods in TodoResource
// @PostAuthorize("returnObject.username == 'dom'")

@Configuration
@EnableMethodSecurity(securedEnabled = true)
public class BasicAuthSecurityConfiguration {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		RequestMatcher optionsMatcher = new AntPathRequestMatcher("/**", HttpMethod.OPTIONS.toString());
		http.authorizeHttpRequests(auth -> auth.requestMatchers(optionsMatcher).permitAll()
				.requestMatchers(new AntPathRequestMatcher("/**")).authenticated());

		http.csrf(csrf -> csrf.disable());

		http.httpBasic(Customizer.withDefaults());

		http.headers().frameOptions().sameOrigin();

		return http.build();
	}

//	@Bean
//	public UserDetailsService userDetailService() {
//		
//		var user = User.withUsername("dom")
//			.password("{noop}dom")
//			.roles("USER")
//			.build();
//
//		
//		var admin = User.withUsername("admin")
//				.password("{noop}dummy")
//				.roles("ADMIN")
//				.build();
//
//		return new InMemoryUserDetailsManager(user, admin);
//	}

	@Bean
	public DataSource dataSource() {
		return new EmbeddedDatabaseBuilder().setType(EmbeddedDatabaseType.H2)
				.addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION).build();
	}

	
	@Bean
	public UserDetailsService userDetailService(DataSource dataSource) {
		
		var user = User.withUsername("dom")
//			.password("{noop}dom")
				.password("dom")
				.passwordEncoder(str -> passwordEncoder().encode(str))
			.roles("USER")
			.build();

		
		var admin = User.withUsername("admin")
//				.password("{noop}dummy")
				.password("dom")
				.passwordEncoder(str -> passwordEncoder().encode(str))
				.roles("ADMIN", "USER")
				.build();
		
		var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
		jdbcUserDetailsManager.createUser(user);
		jdbcUserDetailsManager.createUser(admin);

		return new InMemoryUserDetailsManager(user, admin);
	}
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
