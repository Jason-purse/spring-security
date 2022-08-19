/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.config.annotation.authentication.configuration;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.aop.framework.ProxyFactoryBean;
import org.springframework.aop.target.LazyInitTargetSource;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.JdbcUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.configuration.ObjectPostProcessorConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

/**
 *
 * 这才是认证的核心默认配置 ....
 *
 * Exports the authentication {@link Configuration}
 *
 * 这个配置是在@EnableWebSecurity或者 @EnableGlobalMethodSecurity的时候导入的 ..
 *
 * 它们都会导入 AuthenticationConfiguration ,
 * 这个类暴露了认证配置 ...
 *
 * @author Rob Winch
 * @since 3.2
 *
 */
@Configuration(proxyBeanMethods = false)
@Import(ObjectPostProcessorConfiguration.class)
public class AuthenticationConfiguration {

	private AtomicBoolean buildingAuthenticationManager = new AtomicBoolean();

	private ApplicationContext applicationContext;

	private AuthenticationManager authenticationManager;

	private boolean authenticationManagerInitialized;

	/**
	 * 全局的认证配置适配器 ..
	 */
	private List<GlobalAuthenticationConfigurerAdapter> globalAuthConfigurers = Collections.emptyList();

	private ObjectPostProcessor<Object> objectPostProcessor;

//	暴露一个认证管理器构建器
	// 这是全局的认证管理构建器 ...
	@Bean
	public AuthenticationManagerBuilder authenticationManagerBuilder(ObjectPostProcessor<Object> objectPostProcessor,
			ApplicationContext context) {
		// 懒加载密码编码器是为了 多种密码存储 ...
		LazyPasswordEncoder defaultPasswordEncoder = new LazyPasswordEncoder(context);
		// 认证事件派发器,是提前处理好的 ...(其他的自动配置进行加载)
		AuthenticationEventPublisher authenticationEventPublisher = getBeanOrNull(context,
				AuthenticationEventPublisher.class);
		// 默认的密码编码器认证管理器构建器 ....
		// 也可以看出来 认证管理基于 PasswordEncoder 进行用户校验 ...
		DefaultPasswordEncoderAuthenticationManagerBuilder result = new DefaultPasswordEncoderAuthenticationManagerBuilder(
				objectPostProcessor, defaultPasswordEncoder);
		if (authenticationEventPublisher != null) {
			result.authenticationEventPublisher(authenticationEventPublisher);
		}
		return result;
	}

	// 全局认证配置器适配器 ...
	// 直接 在全局配置
	// 以下三个都是 -----------------------------------
	@Bean
	public static GlobalAuthenticationConfigurerAdapter enableGlobalAuthenticationAutowiredConfigurer(
			ApplicationContext context) {
		return new EnableGlobalAuthenticationAutowiredConfigurer(context);
	}

	// userDetailsService 获取来源
	@Bean
	public static InitializeUserDetailsBeanManagerConfigurer initializeUserDetailsBeanManagerConfigurer(
			ApplicationContext context) {
		return new InitializeUserDetailsBeanManagerConfigurer(context);
	}

	// authenticationProvider bean 获取来源 ..
	@Bean
	public static InitializeAuthenticationProviderBeanManagerConfigurer initializeAuthenticationProviderBeanManagerConfigurer(
			ApplicationContext context) {
		return new InitializeAuthenticationProviderBeanManagerConfigurer(context);
	}

	/**
	 * 这是构建AuthenticationManager的核心 ..
	 * 有一定的逻辑在里面,直接看有点看不懂 ...
	 * @return
	 * @throws Exception
	 */
	public AuthenticationManager getAuthenticationManager() throws Exception {
		if (this.authenticationManagerInitialized) {
			return this.authenticationManager;
		}
		// 顶级认证管理器配置 ...
		AuthenticationManagerBuilder authBuilder = this.applicationContext.getBean(AuthenticationManagerBuilder.class);
		// 如果这里有了Bean,如果我们直接返回AuthenticationManagerBuilder.build 会怎么样,将导致无限递归 ..
		// 为什么呢?? 先留下这个疑问 ..
		// 已经调用过一次了,
		// 第一次 给一个壳子 ...
		if (this.buildingAuthenticationManager.getAndSet(true)) {
			return new AuthenticationManagerDelegator(authBuilder);
		}
		// 全局认证配置适配器 ..
		// 也就是用户配置之后的补丁 ...
		// 保证程序能够正确的配置 。。。
		for (GlobalAuthenticationConfigurerAdapter config : this.globalAuthConfigurers) {
			// 应用 有些增加了一些 (初始化 阶段的configurer) .. 用来提前处理 ..
			authBuilder.apply(config);
		}

		// 然后尝试构建 ...
		// 将所有的 configurer 进行配置 .. 形成完成的authenticationManager ...
		this.authenticationManager = authBuilder.build();

		// 一般来说这不可能 ...
		// 如果说返回的是(全局构建器Manager = null)
		if (this.authenticationManager == null) {
			// 懒加载一个 ....
			this.authenticationManager = getAuthenticationManagerBean();
		}
		// 设置为 true了 ..
		this.authenticationManagerInitialized = true;
		return this.authenticationManager;
	}

	@Autowired(required = false)
	public void setGlobalAuthenticationConfigurers(List<GlobalAuthenticationConfigurerAdapter> configurers) {
		configurers.sort(AnnotationAwareOrderComparator.INSTANCE);
		this.globalAuthConfigurers = configurers;
	}

	@Autowired
	public void setApplicationContext(ApplicationContext applicationContext) {
		this.applicationContext = applicationContext;
	}

	@Autowired
	public void setObjectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
		this.objectPostProcessor = objectPostProcessor;
	}

	@SuppressWarnings("unchecked")
	private <T> T lazyBean(Class<T> interfaceName) {
		LazyInitTargetSource lazyTargetSource = new LazyInitTargetSource();
		String[] beanNamesForType = BeanFactoryUtils.beanNamesForTypeIncludingAncestors(this.applicationContext,
				interfaceName);
		if (beanNamesForType.length == 0) {
			return null;
		}
		String beanName = getBeanName(interfaceName, beanNamesForType);
		lazyTargetSource.setTargetBeanName(beanName);
		lazyTargetSource.setBeanFactory(this.applicationContext);
		ProxyFactoryBean proxyFactory = new ProxyFactoryBean();
		proxyFactory = this.objectPostProcessor.postProcess(proxyFactory);
		proxyFactory.setTargetSource(lazyTargetSource);
		return (T) proxyFactory.getObject();
	}

	private <T> String getBeanName(Class<T> interfaceName, String[] beanNamesForType) {
		if (beanNamesForType.length == 1) {
			return beanNamesForType[0];
		}
		List<String> primaryBeanNames = getPrimaryBeanNames(beanNamesForType);
		Assert.isTrue(primaryBeanNames.size() != 0, () -> "Found " + beanNamesForType.length + " beans for type "
				+ interfaceName + ", but none marked as primary");
		Assert.isTrue(primaryBeanNames.size() == 1,
				() -> "Found " + primaryBeanNames.size() + " beans for type " + interfaceName + " marked as primary");
		return primaryBeanNames.get(0);
	}

	private List<String> getPrimaryBeanNames(String[] beanNamesForType) {
		List<String> list = new ArrayList<>();
		if (!(this.applicationContext instanceof ConfigurableApplicationContext)) {
			return Collections.emptyList();
		}
		for (String beanName : beanNamesForType) {
			if (((ConfigurableApplicationContext) this.applicationContext).getBeanFactory().getBeanDefinition(beanName)
					.isPrimary()) {
				list.add(beanName);
			}
		}
		return list;
	}

	private AuthenticationManager getAuthenticationManagerBean() {
		return lazyBean(AuthenticationManager.class);
	}

	private static <T> T getBeanOrNull(ApplicationContext applicationContext, Class<T> type) {
		try {
			return applicationContext.getBean(type);
		}
		catch (NoSuchBeanDefinitionException notFound) {
			return null;
		}
	}

	private static class EnableGlobalAuthenticationAutowiredConfigurer extends GlobalAuthenticationConfigurerAdapter {

		private final ApplicationContext context;

		private static final Log logger = LogFactory.getLog(EnableGlobalAuthenticationAutowiredConfigurer.class);

		EnableGlobalAuthenticationAutowiredConfigurer(ApplicationContext context) {
			this.context = context;
		}

		@Override
		public void init(AuthenticationManagerBuilder auth) {
			// 被这个注解注释的beans
			Map<String, Object> beansWithAnnotation = this.context
					.getBeansWithAnnotation(EnableGlobalAuthentication.class);
			if (logger.isTraceEnabled()) {
				logger.trace(LogMessage.format("Eagerly initializing %s", beansWithAnnotation));
			}
		}

	}

	/**
	 * Prevents infinite recursion in the event that initializing the
	 * AuthenticationManager.
	 *
	 * @author Rob Winch
	 * @since 4.1.1
	 */
	static final class AuthenticationManagerDelegator implements AuthenticationManager {

		private AuthenticationManagerBuilder delegateBuilder;

		private AuthenticationManager delegate;

		private final Object delegateMonitor = new Object();

		AuthenticationManagerDelegator(AuthenticationManagerBuilder delegateBuilder) {
			Assert.notNull(delegateBuilder, "delegateBuilder cannot be null");
			this.delegateBuilder = delegateBuilder;
		}

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			if (this.delegate != null) {
				return this.delegate.authenticate(authentication);
			}
			synchronized (this.delegateMonitor) {
				if (this.delegate == null) {
					this.delegate = this.delegateBuilder.getObject();
					this.delegateBuilder = null;
				}
			}
			return this.delegate.authenticate(authentication);
		}

		@Override
		public String toString() {
			return "AuthenticationManagerDelegator [delegate=" + this.delegate + "]";
		}

	}

	static class DefaultPasswordEncoderAuthenticationManagerBuilder extends AuthenticationManagerBuilder {

		private PasswordEncoder defaultPasswordEncoder;

		/**
		 * Creates a new instance
		 * @param objectPostProcessor the {@link ObjectPostProcessor} instance to use.
		 */
		DefaultPasswordEncoderAuthenticationManagerBuilder(ObjectPostProcessor<Object> objectPostProcessor,
				PasswordEncoder defaultPasswordEncoder) {
			super(objectPostProcessor);
			this.defaultPasswordEncoder = defaultPasswordEncoder;
		}

		@Override
		public InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> inMemoryAuthentication()
				throws Exception {
			return super.inMemoryAuthentication().passwordEncoder(this.defaultPasswordEncoder);
		}

		@Override
		public JdbcUserDetailsManagerConfigurer<AuthenticationManagerBuilder> jdbcAuthentication() throws Exception {
			return super.jdbcAuthentication().passwordEncoder(this.defaultPasswordEncoder);
		}

		@Override
		public <T extends UserDetailsService> DaoAuthenticationConfigurer<AuthenticationManagerBuilder, T> userDetailsService(
				T userDetailsService) throws Exception {
			return super.userDetailsService(userDetailsService).passwordEncoder(this.defaultPasswordEncoder);
		}

	}

	static class LazyPasswordEncoder implements PasswordEncoder {

		private ApplicationContext applicationContext;

		private PasswordEncoder passwordEncoder;

		LazyPasswordEncoder(ApplicationContext applicationContext) {
			this.applicationContext = applicationContext;
		}

		@Override
		public String encode(CharSequence rawPassword) {
			return getPasswordEncoder().encode(rawPassword);
		}

		@Override
		public boolean matches(CharSequence rawPassword, String encodedPassword) {
			return getPasswordEncoder().matches(rawPassword, encodedPassword);
		}

		@Override
		public boolean upgradeEncoding(String encodedPassword) {
			return getPasswordEncoder().upgradeEncoding(encodedPassword);
		}

		private PasswordEncoder getPasswordEncoder() {
			if (this.passwordEncoder != null) {
				return this.passwordEncoder;
			}
			PasswordEncoder passwordEncoder = getBeanOrNull(this.applicationContext, PasswordEncoder.class);
			if (passwordEncoder == null) {
				passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
			}
			this.passwordEncoder = passwordEncoder;
			return passwordEncoder;
		}

		@Override
		public String toString() {
			return getPasswordEncoder().toString();
		}

	}

}
