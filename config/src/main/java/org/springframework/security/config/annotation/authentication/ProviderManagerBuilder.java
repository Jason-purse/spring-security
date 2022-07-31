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

package org.springframework.security.config.annotation.authentication;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.SecurityBuilder;

/**
 * Interface for operating on a SecurityBuilder that creates a {@link ProviderManager}
 *
 * 在SecurityBuilder 上创建ProviderManager的一个接口 ...
 * @param <B> the type of the {@link SecurityBuilder}
 * @author Rob Winch
 */
public interface ProviderManagerBuilder<B extends ProviderManagerBuilder<B>>
		extends SecurityBuilder<AuthenticationManager> {

	/**
	 * Add authentication based upon the custom {@link AuthenticationProvider} that is
	 * passed in. Since the {@link AuthenticationProvider} implementation is unknown, all
	 * customizations must be done externally and the {@link ProviderManagerBuilder} is
	 * returned immediately.
	 *
	 * 也就是增加一个自定义的AuthenticationProvider(增加认证方式) ..
	 * 由于AuthenticationProvider是未知的,所有的自定义必须完全外部化,并且ProviderManagerBuilder 将立即返回 ..
	 *
	 * Note that an Exception is thrown if an error occurs when adding the
	 * {@link AuthenticationProvider}.
	 * @return a {@link ProviderManagerBuilder} to allow further authentication to be
	 * provided to the {@link ProviderManagerBuilder}   返回一个ProviderManagerBuilder,允许后续认证的时候,提供 ProviderManagerBuilder;
	 */
	B authenticationProvider(AuthenticationProvider authenticationProvider);

}
