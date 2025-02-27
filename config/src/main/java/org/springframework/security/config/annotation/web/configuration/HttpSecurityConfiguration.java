/*
 * Copyright 2002-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.config.annotation.web.configuration;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.core.io.support.SpringFactoriesLoader;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.DefaultLoginPageConfigurer;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * {@link Configuration} that exposes the {@link HttpSecurity} bean.
 *
 * 用来暴露一个HttpSecurity Bean ...
 *
 * 暴露一个 HttpSecurity Bean
 * @author Eleftheria Stein
 * @since 5.4
 */
@Configuration(proxyBeanMethods = false)
class HttpSecurityConfiguration {

	private static final String BEAN_NAME_PREFIX = "org.springframework.security.config.annotation.web.configuration.HttpSecurityConfiguration.";

	private static final String HTTPSECURITY_BEAN_NAME = BEAN_NAME_PREFIX + "httpSecurity";

	private ObjectPostProcessor<Object> objectPostProcessor;

	private AuthenticationManager authenticationManager;

	private AuthenticationConfiguration authenticationConfiguration;

	private ApplicationContext context;

	@Autowired
	void setObjectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
		this.objectPostProcessor = objectPostProcessor;
	}

	void setAuthenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@Autowired
	void setAuthenticationConfiguration(AuthenticationConfiguration authenticationConfiguration) {
		this.authenticationConfiguration = authenticationConfiguration;
	}

	@Autowired
	void setApplicationContext(ApplicationContext context) {
		this.context = context;
	}

	/**
	 * 它将被 Springboot 的SpringBootWebSecurityConfiguration 一个 bean 需要 ..
	 * @return
	 * @throws Exception
	 */
	@Bean(HTTPSECURITY_BEAN_NAME)
	@Scope("prototype")
	HttpSecurity httpSecurity() throws Exception {
		WebSecurityConfigurerAdapter.LazyPasswordEncoder passwordEncoder = new WebSecurityConfigurerAdapter.LazyPasswordEncoder(
				this.context);
		AuthenticationManagerBuilder authenticationBuilder = new WebSecurityConfigurerAdapter.DefaultPasswordEncoderAuthenticationManagerBuilder(
				this.objectPostProcessor, passwordEncoder);

		// 将这个认证管理器的配置加到 当前定义的  AuthenticationManagerBuilder ...
		authenticationBuilder.parentAuthenticationManager(authenticationManager());
		HttpSecurity http = new HttpSecurity(this.objectPostProcessor, authenticationBuilder, createSharedObjects());
		// @formatter:off
		http
			.csrf(withDefaults())
			.addFilter(new WebAsyncManagerIntegrationFilter())
			.exceptionHandling(withDefaults())
			.headers(withDefaults())
			.sessionManagement(withDefaults())
			.securityContext(withDefaults())
			.requestCache(withDefaults())
			.anonymous(withDefaults())
			.servletApi(withDefaults())
			.apply(new DefaultLoginPageConfigurer<>());
		http.logout(withDefaults());
		// @formatter:on
		applyDefaultConfigurers(http);
		return http;
	}

	// 默认拿取认证配置的 认证管理器
	private AuthenticationManager authenticationManager() throws Exception {
		return (this.authenticationManager != null) ? this.authenticationManager
				: this.authenticationConfiguration.getAuthenticationManager();
	}

	private void applyDefaultConfigurers(HttpSecurity http) throws Exception {
		ClassLoader classLoader = this.context.getClassLoader();
		List<AbstractHttpConfigurer> defaultHttpConfigurers = SpringFactoriesLoader
				.loadFactories(AbstractHttpConfigurer.class, classLoader);
		for (AbstractHttpConfigurer configurer : defaultHttpConfigurers) {
			http.apply(configurer);
		}
	}

	/**
	 * 它自己的 共享对象就只有一个应用上下文
	 * @return
	 */
	private Map<Class<?>, Object> createSharedObjects() {
		Map<Class<?>, Object> sharedObjects = new HashMap<>();
		sharedObjects.put(ApplicationContext.class, this.context);
		return sharedObjects;
	}

}
