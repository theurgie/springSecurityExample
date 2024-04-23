package com.in28minutes.learnspringsecurity.jwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

//@Configuration
public class JwtSecurityConfiguration {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		RequestMatcher optionsMatcher = new AntPathRequestMatcher("/**", HttpMethod.OPTIONS.toString());
		http.authorizeHttpRequests(auth -> auth.requestMatchers(optionsMatcher).permitAll()
				.requestMatchers(new AntPathRequestMatcher("/**")).authenticated());

		http.csrf(csrf -> csrf.disable());

		http.httpBasic(Customizer.withDefaults());

		http.headers().frameOptions().sameOrigin();
		
		http.oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()));

		return http.build();
	}

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
	
	@Bean
	public KeyPair keyPair() {
		try {
			var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			return keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}
	
	@Bean
	public RSAKey rsaKey(KeyPair keyPair) {
		
		return new RSAKey
				.Builder((RSAPublicKey)keyPair.getPublic())
				.privateKey(keyPair.getPrivate())
				.keyID(UUID.randomUUID().toString())
				.build();
	}
	
	@Bean
	public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
		var jwkSet = new JWKSet(rsaKey);
		
		// short hand way over overrideing a function using lambda
		// we give it params and what to return
		return (jwkSelector, context) ->  jwkSelector.select(jwkSet);
		
	}
	
	@Bean
	public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
		return NimbusJwtDecoder
				.withPublicKey(rsaKey.toRSAPublicKey())
				.build();
		
	}
	
	@Bean
	public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
		return new NimbusJwtEncoder(jwkSource);
	}
}
