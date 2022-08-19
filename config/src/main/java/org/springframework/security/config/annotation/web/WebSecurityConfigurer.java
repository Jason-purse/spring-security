/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.config.annotation.web;

import jakarta.servlet.Filter;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Allows customization to the {@link WebSecurity}. In most instances users will use
 * {@link EnableWebSecurity} and either create a {@link Configuration} that extends
 * {@link WebSecurityConfigurerAdapter} or expose a {@link SecurityFilterChain} bean. Both
 * will automatically be applied to the {@link WebSecurity} by the
 * {@link EnableWebSecurity} annotation.
 *
 * 这个接口 用来定制 WebSecurity , 在多数情况下用户将使用@EnableWebSecurity 或者 创建一个@Configuration 继承WebSecurityConfigurerAdapter  / 又或者直接暴露一个 SecurityFilterChain ..
 *
 * 它将自动的通过@EnableWebSecurity 自动的应用到 WebSecurity ..
 *
 *
 *
 * 首先,WebSecurityConfiguration 会自动的创建一个 WebSecurity ,然后会通过bean 上下文容器获取所有的 WebSecurityConfigurer ...
 *
 *
 *
 * @author Rob Winch
 * @since 3.2
 * @see WebSecurityConfigurerAdapter
 * @see SecurityFilterChain
 */
public interface WebSecurityConfigurer<T extends SecurityBuilder<Filter>> extends SecurityConfigurer<Filter, T> {

}
