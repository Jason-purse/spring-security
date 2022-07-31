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

package org.springframework.security.config.annotation;

/**
 * Allows for configuring a {@link SecurityBuilder}. All {@link SecurityConfigurer} first
 * have their {@link #init(SecurityBuilder)} method invoked. After all
 * {@link #init(SecurityBuilder)} methods have been invoked, each
 * {@link #configure(SecurityBuilder)} method is invoked.
 *
 * 允许配置一个SecurityBuilder, 所有的 SecurityConfigurer 首先应该让它们的#init(SecurityBuilder)方法执行,也就是初始化构建器 ...
 * 在#init方法执行完毕之后,执行configure(SecurityBuilder) ...
 *
 * @param <O> The object being built by the {@link SecurityBuilder} B
 * @param <B> The {@link SecurityBuilder} that builds objects of type O. This is also the
 * {@link SecurityBuilder} that is being configured.
 * @author Rob Winch
 * @see AbstractConfiguredSecurityBuilder
 */
public interface SecurityConfigurer<O, B extends SecurityBuilder<O>> {

	/**
	 * Initialize the {@link SecurityBuilder}. Here only shared state should be created
	 * and modified, but not properties on the {@link SecurityBuilder} used for building
	 * the object. This ensures that the {@link #configure(SecurityBuilder)} method uses
	 * the correct shared objects when building. Configurers should be applied here.
	 *
	 *
	 * 初始化 {@link SecurityBuilder}。这里只应创建共享状态
	 *  * 并进行修改，但不能创建用于构建
	 *  * 对象的 {@link SecurityBuilder} 上的属性。这可确保 {@link #configure（SecurityBuilder）} 方法在构建时使用
	 *  * 正确的共享对象。此处应应用配置器。
	 * @param builder
	 * @throws Exception
	 */
	void init(B builder) throws Exception;

	/**
	 * Configure the {@link SecurityBuilder} by setting the necessary properties on the
	 * {@link SecurityBuilder}.
	 * @param builder
	 * @throws Exception
	 */
	void configure(B builder) throws Exception;

}
