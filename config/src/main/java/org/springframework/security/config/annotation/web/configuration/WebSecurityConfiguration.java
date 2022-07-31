/*
 * Copyright 2002-2021 the original author or authors.
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

import java.util.Collections;
import java.util.List;
import java.util.Map;

import jakarta.servlet.Filter;

import org.springframework.beans.factory.BeanClassLoaderAware;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.ImportAware;
import org.springframework.core.OrderComparator;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.annotation.Order;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.crypto.RsaKeyConversionServicePostProcessor;
import org.springframework.security.context.DelegatingApplicationListener;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.util.Assert;

/**
 * Uses a {@link WebSecurity} to create the {@link FilterChainProxy} that performs the web
 * based security for Spring Security. It then exports the necessary beans. Customizations
 * can be made to {@link WebSecurity} by extending {@link WebSecurityConfigurerAdapter}
 * and exposing it as a {@link Configuration} or implementing
 * {@link WebSecurityConfigurer} and exposing it as a {@link Configuration}. This
 * configuration is imported when using {@link EnableWebSecurity}.
 *
 * 使用一个 WebSecurity 创建 FilterChainProxy(然后执行基于web的安全)
 * 它将暴露一些必要的bean,通过扩展WebSecurityConfigurerAdapter 实现 WebSecurity的定制并且将它暴露为一个@Configuration或者
 * 实现 WebSecurityConfigurer 然后将它暴露为一个Configuration ... 这个配置在使用@EnableWebSecurity的时候会自动进行导入 ....
 *
 * 因为这个类会收集 List<WebSecurityConfigurer>
 *
 * @author Rob Winch
 * @author Keesun Baik
 * @since 3.2
 * @see EnableWebSecurity
 * @see WebSecurity
 */
@Configuration(proxyBeanMethods = false)
public class WebSecurityConfiguration implements ImportAware, BeanClassLoaderAware {

	/**
	 * web 安全核心 ..
	 */
	private WebSecurity webSecurity;

	private Boolean debugEnabled;

	//	WebSecurityConfigurer 定制
	private List<SecurityConfigurer<Filter, WebSecurity>> webSecurityConfigurers;

	// 多个过滤器链 ..
	private List<SecurityFilterChain> securityFilterChains = Collections.emptyList();

	// webSecurityConstomizer 定制
	private List<WebSecurityCustomizer> webSecurityCustomizers = Collections.emptyList();

	private ClassLoader beanClassLoader;

	/**
	 * 进行后置处理的 一个切入点(没有直接和ApplicationContext捆绑) ..
	 */
	@Autowired(required = false)
	private ObjectPostProcessor<Object> objectObjectPostProcessor;

	/**
	 * 导入了一个 应用监听器 ...
	 * @return
	 */
	@Bean
	public static DelegatingApplicationListener delegatingApplicationListener() {
		return new DelegatingApplicationListener();
	}

	/**
	 * 导入了一个  SecurityExpressionHandler ..
	 * @return
	 */
	@Bean
	@DependsOn(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
	public SecurityExpressionHandler<FilterInvocation> webSecurityExpressionHandler() {
		return this.webSecurity.getExpressionHandler();
	}

	/**
	 * Creates the Spring Security Filter Chain
	 * @return the {@link Filter} that represents the security filter chain
	 * @throws Exception
	 *
	 *
	 * 核心过滤器 ...
	 */
	@Bean(name = AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
	public Filter springSecurityFilterChain() throws Exception {
		boolean hasConfigurers = this.webSecurityConfigurers != null && !this.webSecurityConfigurers.isEmpty();
		boolean hasFilterChain = !this.securityFilterChains.isEmpty();
		Assert.state(!(hasConfigurers && hasFilterChain),
				"Found WebSecurityConfigurerAdapter as well as SecurityFilterChain. Please select just one.");

		// 当不存在 定制和 过滤器链的时候... 默认创建一个 ...
		// 也就是从这里,我们看出了,spring security 团队建议我们直接注入httpSecurity 暴露 securityFilterChain的原因 ...
		// 如果我们没有使用这种方式,采用了 WebSecurityConfigurerAdapter继承的形式,那么 就相当于使用我们自己的 WebSecurityConfigurerAdapter(作为一个bean,也 直接被ioc容器处理了,也就没必要默认添加一个WebSecurityConfigurerAdapter ).
		if (!hasConfigurers && !hasFilterChain) {
			// 然后通过后置处理器进行了后置处理,比较特殊 ..
			// 如果采用默认的形式 ...
			WebSecurityConfigurerAdapter adapter = this.objectObjectPostProcessor
					.postProcess(new WebSecurityConfigurerAdapter() {
					});
			this.webSecurity.apply(adapter);
		}
		// 直接加入
		for (SecurityFilterChain securityFilterChain : this.securityFilterChains) {
			this.webSecurity.addSecurityFilterChainBuilder(() -> securityFilterChain);
			for (Filter filter : securityFilterChain.getFilters()) {

				// 如果我们自己的过滤链提供了 FilterSecurityInterceptor,则设置 .. 但是一般是通过 WebSecurityConfigurerAdapter ..后置处理 ...
				if (filter instanceof FilterSecurityInterceptor) {
					this.webSecurity.securityInterceptor((FilterSecurityInterceptor) filter);
					break;
				}
			}
		}

		// 前面通过SecurityConfigurer 定制了 WebSecurity ...
		// 这里由于提供了两种方式,它也许需要定制webSecurity
		// (一般我们使用了configurer 以及 构建了 securityFilterChain ,不可能再使用 customizer ...)
		for (WebSecurityCustomizer customizer : this.webSecurityCustomizers) {
			customizer.customize(this.webSecurity);
		}

		// 最终开始 build,我们直接查看 performBuild()
		return this.webSecurity.build();
	}

	/**
	 * Creates the {@link WebInvocationPrivilegeEvaluator} that is necessary to evaluate
	 * privileges for a given web URI
	 * @return the {@link WebInvocationPrivilegeEvaluator}
	 */
	@Bean
	@DependsOn(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
	public WebInvocationPrivilegeEvaluator privilegeEvaluator() {
		return this.webSecurity.getPrivilegeEvaluator();
	}



	/**
	 * 核心点在 这个@Configuration的自身处理完毕之后,然后@Autowired的时候  进行WebSecurity的构建 ...
	 * 并设置 SecurityConfigurer<FilterChainProxy,WebSecurityBuilder> 进行web配置 ...
	 *
	 * 	webSecurity 核心入口 ..
	 *
	 * Sets the {@code <SecurityConfigurer<FilterChainProxy, WebSecurityBuilder>}
	 * instances used to create the web configuration.
	 * @param objectPostProcessor the {@link ObjectPostProcessor} used to create a
	 * {@link WebSecurity} instance
	 * @param beanFactory the bean factory to use to retrieve the relevant
	 * {@code <SecurityConfigurer<FilterChainProxy, WebSecurityBuilder>} instances used to
	 * create the web configuration
	 * @throws Exception
	 */
	@Autowired(required = false)
	public void setFilterChainProxySecurityConfigurer(ObjectPostProcessor<Object> objectPostProcessor,
			ConfigurableListableBeanFactory beanFactory) throws Exception {

		// 这个ObjectPostProcessor AuthenticationConfiguration 的导入  ..
		this.webSecurity = objectPostProcessor.postProcess(new WebSecurity(objectPostProcessor));
		// importMetaData 的处理 ..
		if (this.debugEnabled != null) {
			this.webSecurity.debug(this.debugEnabled);
		}


		List<SecurityConfigurer<Filter, WebSecurity>> webSecurityConfigurers = new AutowiredWebSecurityConfigurersIgnoreParents(
				beanFactory).getWebSecurityConfigurers();

		// 根据Order 进行排序 ..
		webSecurityConfigurers.sort(AnnotationAwareOrderComparator.INSTANCE);
		Integer previousOrder = null;
		Object previousConfig = null;

		// 进行判断, 顺序必须唯一 ..
		for (SecurityConfigurer<Filter, WebSecurity> config : webSecurityConfigurers) {
			Integer order = AnnotationAwareOrderComparator.lookupOrder(config);
			if (previousOrder != null && previousOrder.equals(order)) {
				throw new IllegalStateException("@Order on WebSecurityConfigurers must be unique. Order of " + order
						+ " was already used on " + previousConfig + ", so it cannot be used on " + config + " too.");
			}
			previousOrder = order;
			previousConfig = config;
		}

		// 问题就来了,如何收集的这些构建器 ..
		// 也就是我们向 容器中注入的 SecurityConfigurer<Filter, WebSecurity>, 我们可以对WebSecurity 进行配置 ...
		for (SecurityConfigurer<Filter, WebSecurity> webSecurityConfigurer : webSecurityConfigurers) {
			// 开始应用 ... (入口)
			this.webSecurity.apply(webSecurityConfigurer);
		}
		this.webSecurityConfigurers = webSecurityConfigurers;
	}

	@Autowired(required = false)
	void setFilterChains(List<SecurityFilterChain> securityFilterChains) {
		this.securityFilterChains = securityFilterChains;
	}

	@Autowired(required = false)
	void setWebSecurityCustomizers(List<WebSecurityCustomizer> webSecurityCustomizers) {
		this.webSecurityCustomizers = webSecurityCustomizers;
	}


	// 然后包含了 RsaKeyConversionServicePostProcessor 后置处理 ..
	@Bean
	public static BeanFactoryPostProcessor conversionServicePostProcessor() {
		return new RsaKeyConversionServicePostProcessor();
	}

	/**
	 * 由于它是导入的,它可以接收导入对象的注解元数据 ...
	 * @param importMetadata
	 */
	@Override
	public void setImportMetadata(AnnotationMetadata importMetadata) {

		// 获取注解属性 ...
		Map<String, Object> enableWebSecurityAttrMap = importMetadata
				.getAnnotationAttributes(EnableWebSecurity.class.getName());

		// 然后转化为map 进行解析 ...
		AnnotationAttributes enableWebSecurityAttrs = AnnotationAttributes.fromMap(enableWebSecurityAttrMap);
		this.debugEnabled = enableWebSecurityAttrs.getBoolean("debug");
		if (this.webSecurity != null) {
			this.webSecurity.debug(this.debugEnabled);
		}
	}

	@Override
	public void setBeanClassLoader(ClassLoader classLoader) {
		this.beanClassLoader = classLoader;
	}

	/**
	 * A custom version of the Spring provided AnnotationAwareOrderComparator that uses
	 * {@link AnnotationUtils#findAnnotation(Class, Class)} to look on super class
	 * instances for the {@link Order} annotation.
	 *
	 * @author Rob Winch
	 * @since 3.2
	 */
	private static class AnnotationAwareOrderComparator extends OrderComparator {

		private static final AnnotationAwareOrderComparator INSTANCE = new AnnotationAwareOrderComparator();

		@Override
		protected int getOrder(Object obj) {
			return lookupOrder(obj);
		}

		private static int lookupOrder(Object obj) {
			if (obj instanceof Ordered) {
				return ((Ordered) obj).getOrder();
			}
			if (obj != null) {
				Class<?> clazz = ((obj instanceof Class) ? (Class<?>) obj : obj.getClass());
				Order order = AnnotationUtils.findAnnotation(clazz, Order.class);
				if (order != null) {
					return order.value();
				}
			}
			return Ordered.LOWEST_PRECEDENCE;
		}

	}

}
