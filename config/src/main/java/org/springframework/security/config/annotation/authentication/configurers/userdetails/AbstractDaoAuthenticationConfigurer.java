/*
 * Copyright 2002-2013 the original author or authors.
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

package org.springframework.security.config.annotation.authentication.configurers.userdetails;

import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Allows configuring a {@link DaoAuthenticationProvider}
 * 配置一个 DaoAuthenticationProvider(它是核心的基于用户密码的认证提供器)
 * 这里同样通过 Configurer的形式 绑定给AuthenticationManager  ..
 * 在使用UserDetailsManager的时候,被 DaoAuthenticationProvider代理了 ...
 *
 * @param <B> the type of the {@link SecurityBuilder}
 * @param <C> the type of {@link AbstractDaoAuthenticationConfigurer} this is
 * @param <U> The type of {@link UserDetailsService} that is being used
 * @author Rob Winch
 * @since 3.2
 *
 * 由于 UserDetailsService 是抽象化的,我们继续抽象 ..所以 U 还是泛型 ...
 */
public abstract class AbstractDaoAuthenticationConfigurer<B extends ProviderManagerBuilder<B>, C extends AbstractDaoAuthenticationConfigurer<B, C, U>, U extends UserDetailsService>
		extends UserDetailsAwareConfigurer<B, U> {

	// 我们可以发现,它在这里默认构造了DaoAuthenticationProvider ..
	private DaoAuthenticationProvider provider = new DaoAuthenticationProvider();

	// 以及userDetailService
	private final U userDetailsService;

	/**
	 * Creates a new instance
	 * @param userDetailsService
	 */
	AbstractDaoAuthenticationConfigurer(U userDetailsService) {
		this.userDetailsService = userDetailsService;
		this.provider.setUserDetailsService(userDetailsService);
		if (userDetailsService instanceof UserDetailsPasswordService) {
			// 两种类型的UserDetailsService ...
			this.provider.setUserDetailsPasswordService((UserDetailsPasswordService) userDetailsService);
		}
	}

	/**
	 * 可以进行后置处理(对构造的对象) ...
	 *
	 * Adds an {@link ObjectPostProcessor} for this class.
	 * @param objectPostProcessor
	 * @return the {@link AbstractDaoAuthenticationConfigurer} for further customizations
	 */
	@SuppressWarnings("unchecked")
	public C withObjectPostProcessor(ObjectPostProcessor<?> objectPostProcessor) {
		addObjectPostProcessor(objectPostProcessor);
		return (C) this;
	}

	/**
	 * Allows specifying the {@link PasswordEncoder} to use with the
	 * {@link DaoAuthenticationProvider}. The default is to use plain text.
	 * @param passwordEncoder The {@link PasswordEncoder} to use.
	 * @return the {@link AbstractDaoAuthenticationConfigurer} for further customizations
	 */
	@SuppressWarnings("unchecked")
	public C passwordEncoder(PasswordEncoder passwordEncoder) {
		this.provider.setPasswordEncoder(passwordEncoder);
		return (C) this;
	}

	public C userDetailsPasswordManager(UserDetailsPasswordService passwordManager) {
		this.provider.setUserDetailsPasswordService(passwordManager);
		return (C) this;
	}

	@Override
	public void configure(B builder) throws Exception {
		// 配置的时候,就会进行 后置处理 ....
		this.provider = postProcess(this.provider);
		// 例如这个为AuthenticationManager构建器增加了 AuthenticationProvider
		// 由于ProviderManager ...代理了AuthenticationManager 接口,所以看起来是为 ProviderManager 增加AuthenticationProvider ..
		builder.authenticationProvider(this.provider);
	}

	/**
	 * Gets the {@link UserDetailsService} that is used with the
	 * {@link DaoAuthenticationProvider}
	 * @return the {@link UserDetailsService} that is used with the
	 * {@link DaoAuthenticationProvider}
	 */
	@Override
	public U getUserDetailsService() {
		return this.userDetailsService;
	}

}
