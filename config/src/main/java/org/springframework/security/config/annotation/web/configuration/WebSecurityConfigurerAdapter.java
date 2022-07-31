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

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.aop.TargetSource;
import org.springframework.aop.framework.Advised;
import org.springframework.aop.target.LazyInitTargetSource;
import org.springframework.beans.FatalBeanException;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.support.SpringFactoriesLoader;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.JdbcUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.DefaultLoginPageConfigurer;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.util.Assert;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

/**
 * Provides a convenient base class for creating a {@link WebSecurityConfigurer} instance.
 * The implementation allows customization by overriding methods.
 *
 * <p>
 * Will automatically apply the result of looking up {@link AbstractHttpConfigurer} from
 * {@link SpringFactoriesLoader} to allow developers to extend the defaults. To do this,
 * you must create a class that extends AbstractHttpConfigurer and then create a file in
 * the classpath at "META-INF/spring.factories" that looks something like:
 * </p>
 * <pre>
 * org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer = sample.MyClassThatExtendsAbstractHttpConfigurer
 * </pre> If you have multiple classes that should be added you can use "," to separate
 * the values. For example:
 *
 * <pre>
 * org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer = sample.MyClassThatExtendsAbstractHttpConfigurer, sample.OtherThatExtendsAbstractHttpConfigurer
 * </pre>
 *
 * 尝试查看 WebSecurityConfigurerAdapter ...
 * 它提供了一个方便的基类创建 WebSecurityConfigurer 实例, 这个实现 允许覆盖方法进行定制 ...
 *
 *
 * @author Rob Winch
 * @see EnableWebSecurity
 * @deprecated Use a {@link org.springframework.security.web.SecurityFilterChain} Bean to
 * configure {@link HttpSecurity} or a {@link WebSecurityCustomizer} Bean to configure
 * {@link WebSecurity}
 *
 *
 * 现在已经不建议使用这个,而是直接使用 SecurityFilterChain 配置 HttpSecurity 或者通过 WebSecurityCustomizer Bean配置 WebSecurity ...
 * 但是本质上,这个类就是一个 WebSecurityConfigurer<WebSecurity> ,想想也不知道为什么说这样的话 ...
 *
 * 由于它是一个 WebSecurityConfigurer,那么它包含了configure方法,这个方法在 构建器build的时候,会自行全部执行 ....
 * 例如 构建 WebSecurity
 */
@Order(100)
@Deprecated
public abstract class WebSecurityConfigurerAdapter implements WebSecurityConfigurer<WebSecurity> {

	private final Log logger = LogFactory.getLog(WebSecurityConfigurerAdapter.class);

	private ApplicationContext context;

	private ContentNegotiationStrategy contentNegotiationStrategy = new HeaderContentNegotiationStrategy();

	/**
	 * 这是一个兜底后置处理器 .. 它应该会尝试注入一个新的
	 */
	private ObjectPostProcessor<Object> objectPostProcessor = new ObjectPostProcessor<Object>() {
		@Override
		public <T> T postProcess(T object) {
			throw new IllegalStateException(ObjectPostProcessor.class.getName()
					+ " is a required bean. Ensure you have used @EnableWebSecurity and @Configuration");
		}
	};

	/**
	 * 认证配置
	 */
	private AuthenticationConfiguration authenticationConfiguration;

	/**
	 * 认证管理器构建器
	 */
	private AuthenticationManagerBuilder authenticationBuilder;

	/**
	 * 局部的认证管理器配置器 ..(很显然这个应该是我们自己创建的)
	 */
	private AuthenticationManagerBuilder localConfigureAuthenticationBldr;

	/**
	 * 禁用本地配置 ...
	 */
	private boolean disableLocalConfigureAuthenticationBldr;

	/**
	 * 认证管理器是否初始化 ...
	 */
	private boolean authenticationManagerInitialized;

	/**
	 * 认证管理器 ...
	 */
	private AuthenticationManager authenticationManager;

	/**
	 * 认证评估解析器
	 */
	private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

	/**
	 * http security
	 */
	private HttpSecurity http;

	/**
	 * (默认配置) 是否禁用
	 */
	private boolean disableDefaults;

	/**
	 * Creates an instance with the default configuration enabled.
	 */
	protected WebSecurityConfigurerAdapter() {
		this(false);
	}

	/**
	 * Creates an instance which allows specifying if the default configuration should be
	 * enabled. Disabling the default configuration should be considered more advanced
	 * usage as it requires more understanding of how the framework is implemented.
	 * @param disableDefaults true if the default configuration should be disabled, else
	 * false(表示 默认配置应该被禁用,否则表示false)
	 */
	protected WebSecurityConfigurerAdapter(boolean disableDefaults) {
		this.disableDefaults = disableDefaults;
	}

	/**
	 * Used by the default implementation of {@link #authenticationManager()} to attempt
	 * to obtain an {@link AuthenticationManager}. If overridden, the
	 * {@link AuthenticationManagerBuilder} should be used to specify the
	 * {@link AuthenticationManager}.
	 *
	 * 它的意思就是,这个方法如果被覆盖(则表示用户的 authenticationManager构建是本地构建) 它默认是禁用的 ..
	 * 所以它说需要覆盖方法通过此builder进行  authenticationManager的构建 ...
	 *
	 * <p>
	 * The {@link #authenticationManagerBean()} method can be used to expose the resulting
	 * {@link AuthenticationManager} as a Bean. The {@link #userDetailsServiceBean()} can
	 * be used to expose the last populated {@link UserDetailsService} that is created
	 * with the {@link AuthenticationManagerBuilder} as a Bean. The
	 * {@link UserDetailsService} will also automatically be populated on
	 * {@link HttpSecurity#getSharedObject(Class)} for use with other
	 * {@link SecurityContextConfigurer} (i.e. RememberMeConfigurer )
	 * </p>
	 *
	 * 然后 authenticationManagerBean 能够被用来暴露最终的 AuthenticationManager 作为一个 bean ..
	 *
	 *userDetailsServiceBean 方法能够被用来暴露最后收集的 UserDetailsService (它是由AuthenticationManagerBuilder创建的)作为一个bean ...
	 * 这个UserDetailsService 将自动的收集到 HttpSecurity#getSharedObject(class) 能够被其他的SecurityContextConfigurer 共用 ... 例如 RememberMeConfigurer ...
	 * 当然这是默认行为,你可以选择 覆盖暴露自己的自定义bean ...
	 * <p>
	 * For example, the following configuration could be used to register in memory
	 * authentication that exposes an in memory {@link UserDetailsService}:
	 * </p>
	 *	举个例子,这下面的配置将能够被用来注册一个内存型的认证(通过暴露一个内存型的UserDetailsService) ...
	 * <pre>
	 * &#064;Override
	 * protected void configure(AuthenticationManagerBuilder auth) {
	 * 	auth
	 * 	// enable in memory based authentication with a user named
	 * 	// &quot;user&quot; and &quot;admin&quot;
	 * 	.inMemoryAuthentication().withUser(&quot;user&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;).and()
	 * 			.withUser(&quot;admin&quot;).password(&quot;password&quot;).roles(&quot;USER&quot;, &quot;ADMIN&quot;);
	 * }
	 *
	 * // Expose the UserDetailsService as a Bean
	 * &#064;Bean
	 * &#064;Override
	 * public UserDetailsService userDetailsServiceBean() throws Exception {
	 * 	return super.userDetailsServiceBean();
	 * }
	 *
	 * </pre>
	 * @param auth the {@link AuthenticationManagerBuilder} to use
	 * @throws Exception
	 */
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		this.disableLocalConfigureAuthenticationBldr = true;
	}

	/**
	 * Creates the {@link HttpSecurity} or returns the current instance
	 * @return the {@link HttpSecurity}
	 * @throws Exception
	 */
	@SuppressWarnings({ "rawtypes", "unchecked" })
	protected final HttpSecurity getHttp() throws Exception {
		// 保护判断
		if (this.http != null) {
			return this.http;
		}
		// 开始调用这个方法 ..获取应用事件派发器 ..
		AuthenticationEventPublisher eventPublisher = getAuthenticationEventPublisher();
		// 加入到本地认证构建器中 ..
		this.localConfigureAuthenticationBldr.authenticationEventPublisher(eventPublisher);
		// 获取认证管理器(如果它这个 WebSecurityConfigurerAdapter 是由用户覆盖配置 的,那么它如果覆盖了configure(则表示用户有自己的 AuthenticationManager 构建) .. 这里面将会调用build
		AuthenticationManager authenticationManager = authenticationManager();

		// 拿到之后,则将这个构建出来的manager 作为 当前这个类的认证管理器构建器的父实例 ..
		// 也就是会代理后面的行为 .(认证行为)
		this.authenticationBuilder.parentAuthenticationManager(authenticationManager);
		// 然后尝试获取 共享对象
		Map<Class<?>, Object> sharedObjects = createSharedObjects();

		// 然后开始创建 HttpSecurity
		this.http = new HttpSecurity(this.objectPostProcessor, this.authenticationBuilder, sharedObjects);

		// 如果默认禁用
		if (!this.disableDefaults) {
			// 也就是默认配置 ...
			applyDefaultConfiguration(this.http);

			// 并且我们还使用的上下文的类加载器
			ClassLoader classLoader = this.context.getClassLoader();
			// 然后从Spring SPI 中获取 AbstractHttpConfigurer ...
			// 一般来说,应该是没有的
			List<AbstractHttpConfigurer> defaultHttpConfigurers = SpringFactoriesLoader
					.loadFactories(AbstractHttpConfigurer.class, classLoader);
			for (AbstractHttpConfigurer configurer : defaultHttpConfigurers) {
				this.http.apply(configurer);
			}
		}
		// 然后开始调用 configure(this.http) ....
		configure(this.http);
		return this.http;
	}

	private void applyDefaultConfiguration(HttpSecurity http) throws Exception {
		http.csrf();
		http.addFilter(new WebAsyncManagerIntegrationFilter());
		http.exceptionHandling();
		http.headers();
		http.sessionManagement();
		http.securityContext();
		http.requestCache();
		http.anonymous();
		http.servletApi();
		http.apply(new DefaultLoginPageConfigurer<>());
		http.logout();
	}

	/**
	 * Override this method to expose the {@link AuthenticationManager} from
	 * {@link #configure(AuthenticationManagerBuilder)} to be exposed as a Bean. For
	 * example:
	 *
	 * <pre>
	 * &#064;Bean(name name="myAuthenticationManager")
	 * &#064;Override
	 * public AuthenticationManager authenticationManagerBean() throws Exception {
	 *     return super.authenticationManagerBean();
	 * }
	 * </pre>
	 * @return the {@link AuthenticationManager}
	 * @throws Exception
	 */
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return new AuthenticationManagerDelegator(this.authenticationBuilder, this.context);
	}

	/**
	 * Gets the {@link AuthenticationManager} to use. The default strategy is if
	 * {@link #configure(AuthenticationManagerBuilder)} method is overridden to use the
	 * {@link AuthenticationManagerBuilder} that was passed in. Otherwise, autowire the
	 * {@link AuthenticationManager} by type.
	 *
	 *
	 * 这里它提供了一个方法(可以获取 AuthenticationManager 使用),默认的策略是(如果 configure(....builder)方法被覆盖使用 传递的 AuthenticationManagerBuilder) ..
	 * 否则通过类型自动注入 ...
	 * @return the {@link AuthenticationManager} to use
	 * @throws Exception
	 */
	protected AuthenticationManager authenticationManager() throws Exception {
		// 如果没有初始化 ...
		if (!this.authenticationManagerInitialized) {
			// 尝试配置
			configure(this.localConfigureAuthenticationBldr);

			// 表示没有覆盖,那么 我们就从 authenticationConfiguration(它是全局authenticationManager配置)
			if (this.disableLocalConfigureAuthenticationBldr) {
				// 然后从这里去获取 ..
				this.authenticationManager = this.authenticationConfiguration.getAuthenticationManager();
			}
			else {
				// 否则就是本地Builder 进行构建了 ... (也就是使用用户基于 这个类的实现覆盖) ...
				this.authenticationManager = this.localConfigureAuthenticationBldr.build();
			}
			// 然后同样设置 初始化完毕 ..
			this.authenticationManagerInitialized = true;
		}
		return this.authenticationManager;
	}

	/**
	 * Override this method to expose a {@link UserDetailsService} created from
	 * {@link #configure(AuthenticationManagerBuilder)} as a bean. In general only the
	 * following override should be done of this method:
	 *
	 * <pre>
	 * &#064;Bean(name = &quot;myUserDetailsService&quot;)
	 * // any or no name specified is allowed
	 * &#064;Override
	 * public UserDetailsService userDetailsServiceBean() throws Exception {
	 * 	return super.userDetailsServiceBean();
	 * }
	 * </pre>
	 *
	 * To change the instance returned, developers should change
	 * {@link #userDetailsService()} instead
	 * @return the {@link UserDetailsService}
	 * @throws Exception
	 * @see #userDetailsService()
	 */
	public UserDetailsService userDetailsServiceBean() throws Exception {
		// 它的默认形式,还是从上下文获取
		AuthenticationManagerBuilder globalAuthBuilder = this.context.getBean(AuthenticationManagerBuilder.class);
		return new UserDetailsServiceDelegator(Arrays.asList(this.localConfigureAuthenticationBldr, globalAuthBuilder));
	}

	/**
	 * Allows modifying and accessing the {@link UserDetailsService} from
	 * {@link #userDetailsServiceBean()} without interacting with the
	 * {@link ApplicationContext}. Developers should override this method when changing
	 * the instance of {@link #userDetailsServiceBean()}.
	 *
	 *
	 * 本质上这两个方法都是同样的代码逻辑(它也说了,如果覆盖了userDetailsServiceBean,也需要覆盖这个方法) ...
	 * @return the {@link UserDetailsService} to use
	 */
	protected UserDetailsService userDetailsService() {
		AuthenticationManagerBuilder globalAuthBuilder = this.context.getBean(AuthenticationManagerBuilder.class);
		return new UserDetailsServiceDelegator(Arrays.asList(this.localConfigureAuthenticationBldr, globalAuthBuilder));
	}

	/**
	 * 此configurer的核心入口方法 .. (生命周期之一)
	 * @param web
	 * @throws Exception
	 */
	@Override
	public void init(WebSecurity web) throws Exception {
		// 首先它先创建  HttpSecurity
		HttpSecurity http = getHttp();

		// 拿出来之后,增加
		web.addSecurityFilterChainBuilder(http).postBuildAction(() -> {
			// 完毕之后 ...
			FilterSecurityInterceptor securityInterceptor = http.getSharedObject(FilterSecurityInterceptor.class);
			// 加这个 FilterSecurityInterceptor 加入到 webSecurity
			web.securityInterceptor(securityInterceptor);
		});
	}

	/**
	 * Override this method to configure {@link WebSecurity}. For example, if you wish to
	 * ignore certain requests.
	 *
	 * Endpoints specified in this method will be ignored by Spring Security, meaning it
	 * will not protect them from CSRF, XSS, Clickjacking, and so on.
	 *
	 * Instead, if you want to protect endpoints against common vulnerabilities, then see
	 * {@link #configure(HttpSecurity)} and the {@link HttpSecurity#authorizeRequests}
	 * configuration method.
	 */
	@Override
	public void configure(WebSecurity web) throws Exception {
	}

	/**
	 * Override this method to configure the {@link HttpSecurity}. Typically subclasses
	 * should not invoke this method by calling super as it may override their
	 * configuration. The default configuration is:
	 *
	 * <pre>
	 * http.authorizeRequests().anyRequest().authenticated().and().formLogin().and().httpBasic();
	 * </pre>
	 *
	 * Any endpoint that requires defense against common vulnerabilities can be specified
	 * here, including public ones. See {@link HttpSecurity#authorizeRequests} and the
	 * `permitAll()` authorization rule for more details on public endpoints.
	 * @param http the {@link HttpSecurity} to modify
	 * @throws Exception if an error occurs
	 */
	protected void configure(HttpSecurity http) throws Exception {
		this.logger.debug("Using default configure(HttpSecurity). "
				+ "If subclassed this will potentially override subclass configure(HttpSecurity).");
		http.authorizeRequests((requests) -> requests.anyRequest().authenticated());
		http.formLogin();
		http.httpBasic();
	}

	/**
	 * Gets the ApplicationContext
	 * @return the context
	 */
	protected final ApplicationContext getApplicationContext() {
		return this.context;
	}


	/**
	 * 例如在它设置应用上下文的时候 ,就从上下文获取了 ObjectPostProcessor ...
	 * @param context
	 */
	@Autowired
	public void setApplicationContext(ApplicationContext context) {
		this.context = context;
		// 这里直接拿的原因是(它本身如果被ObjectPostProcessor 执行生命周期过程,Aware是比 自动装配快的) ..
		ObjectPostProcessor<Object> objectPostProcessor = context.getBean(ObjectPostProcessor.class);
		// 然后自己new了一个LazyPasswordEncoder
		// 其实这个密码编码器和 AuthenticationConfiguration中的相差无己,不知道它为什么要这样做,可能避免对AuthenticationConfiguration的强依赖把 ...
		LazyPasswordEncoder passwordEncoder = new LazyPasswordEncoder(context);
		// 然后它自己new出了一个 ..  DefaultPasswordEncoderAuthenticationManagerBuilder
		this.authenticationBuilder = new DefaultPasswordEncoderAuthenticationManagerBuilder(objectPostProcessor,
				passwordEncoder);
		// 同样 本地的配置 也new 了一个 ...
		this.localConfigureAuthenticationBldr = new DefaultPasswordEncoderAuthenticationManagerBuilder(
				objectPostProcessor, passwordEncoder) {

			@Override
			public AuthenticationManagerBuilder eraseCredentials(boolean eraseCredentials) {
				WebSecurityConfigurerAdapter.this.authenticationBuilder.eraseCredentials(eraseCredentials);
				return super.eraseCredentials(eraseCredentials);
			}

			@Override
			public AuthenticationManagerBuilder authenticationEventPublisher(
					AuthenticationEventPublisher eventPublisher) {
				WebSecurityConfigurerAdapter.this.authenticationBuilder.authenticationEventPublisher(eventPublisher);
				return super.authenticationEventPublisher(eventPublisher);
			}

		};
	}

	@Autowired(required = false)
	public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
		this.trustResolver = trustResolver;
	}

	@Autowired(required = false)
	public void setContentNegotationStrategy(ContentNegotiationStrategy contentNegotiationStrategy) {
		this.contentNegotiationStrategy = contentNegotiationStrategy;
	}

	/**
	 * 同样依赖了它 ..
	 * @param objectPostProcessor ...
	 */
	@Autowired
	public void setObjectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
		this.objectPostProcessor = objectPostProcessor;
	}

	@Autowired
	public void setAuthenticationConfiguration(AuthenticationConfiguration authenticationConfiguration) {
		this.authenticationConfiguration = authenticationConfiguration;
	}

	private AuthenticationEventPublisher getAuthenticationEventPublisher() {
		// 同样它从应用上下文中获取一个认证事件派发器 ...
		if (this.context.getBeanNamesForType(AuthenticationEventPublisher.class).length > 0) {
			return this.context.getBean(AuthenticationEventPublisher.class);
		}
		// 否则 自己new 一个 ...
		return this.objectPostProcessor.postProcess(new DefaultAuthenticationEventPublisher());
	}

	/**
	 * 我们来看一下,它的共享对象的初始化 形式
	 * Creates the shared objects
	 * @return the shared Objects
	 */
	private Map<Class<?>, Object> createSharedObjects() {
		Map<Class<?>, Object> sharedObjects = new HashMap<>();
		// 本地配置认证builder的所有共享对象全部加入
		sharedObjects.putAll(this.localConfigureAuthenticationBldr.getSharedObjects());
		// userService ...
		// 当然这里的userDetailsService(如果没有覆盖,它是一个代理器,等到最后authenticationManager 构建完毕之后在获取)
		sharedObjects.put(UserDetailsService.class, userDetailsService());
		// 应用上下文 ...
		sharedObjects.put(ApplicationContext.class, this.context);
		// 内容协商策略
		sharedObjects.put(ContentNegotiationStrategy.class, this.contentNegotiationStrategy);
		// 认证 token 解析器
		sharedObjects.put(AuthenticationTrustResolver.class, this.trustResolver);
		return sharedObjects;
	}

	/**
	 * Delays the use of the {@link UserDetailsService} from the
	 * {@link AuthenticationManagerBuilder} to ensure that it has been fully configured.
	 *
	 * @author Rob Winch
	 * @since 3.2
	 */
	static final class UserDetailsServiceDelegator implements UserDetailsService {

		private List<AuthenticationManagerBuilder> delegateBuilders;

		private UserDetailsService delegate;

		private final Object delegateMonitor = new Object();

		UserDetailsServiceDelegator(List<AuthenticationManagerBuilder> delegateBuilders) {
			Assert.isTrue(!delegateBuilders.contains(null),
					() -> "delegateBuilders cannot contain null values. Got " + delegateBuilders);
			this.delegateBuilders = delegateBuilders;
		}

		@Override
		public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
			if (this.delegate != null) {
				return this.delegate.loadUserByUsername(username);
			}
			synchronized (this.delegateMonitor) {
				if (this.delegate == null) {
					for (AuthenticationManagerBuilder delegateBuilder : this.delegateBuilders) {
						this.delegate = delegateBuilder.getDefaultUserDetailsService();
						if (this.delegate != null) {
							break;
						}
					}
					if (this.delegate == null) {
						throw new IllegalStateException("UserDetailsService is required.");
					}
					this.delegateBuilders = null;
				}
			}
			return this.delegate.loadUserByUsername(username);
		}

	}

	/**
	 * Delays the use of the {@link AuthenticationManager} build from the
	 * {@link AuthenticationManagerBuilder} to ensure that it has been fully configured.
	 *
	 * @author Rob Winch
	 * @since 3.2
	 */
	static final class AuthenticationManagerDelegator implements AuthenticationManager {

		private AuthenticationManagerBuilder delegateBuilder;

		private AuthenticationManager delegate;

		private final Object delegateMonitor = new Object();

		private Set<String> beanNames;

		AuthenticationManagerDelegator(AuthenticationManagerBuilder delegateBuilder, ApplicationContext context) {
			Assert.notNull(delegateBuilder, "delegateBuilder cannot be null");
			Field parentAuthMgrField = ReflectionUtils.findField(AuthenticationManagerBuilder.class,
					"parentAuthenticationManager");
			ReflectionUtils.makeAccessible(parentAuthMgrField);
			this.beanNames = getAuthenticationManagerBeanNames(context);
			validateBeanCycle(ReflectionUtils.getField(parentAuthMgrField, delegateBuilder), this.beanNames);
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

		private static Set<String> getAuthenticationManagerBeanNames(ApplicationContext applicationContext) {
			String[] beanNamesForType = BeanFactoryUtils.beanNamesForTypeIncludingAncestors(applicationContext,
					AuthenticationManager.class);
			return new HashSet<>(Arrays.asList(beanNamesForType));
		}

		private static void validateBeanCycle(Object auth, Set<String> beanNames) {
			if (auth == null || beanNames.isEmpty() || !(auth instanceof Advised)) {
				return;
			}
			TargetSource targetSource = ((Advised) auth).getTargetSource();
			if (!(targetSource instanceof LazyInitTargetSource)) {
				return;
			}
			LazyInitTargetSource lits = (LazyInitTargetSource) targetSource;
			if (beanNames.contains(lits.getTargetBeanName())) {
				throw new FatalBeanException(
						"A dependency cycle was detected when trying to resolve the AuthenticationManager. "
								+ "Please ensure you have configured authentication.");
			}
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
			PasswordEncoder passwordEncoder = getBeanOrNull(PasswordEncoder.class);
			if (passwordEncoder == null) {
				passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
			}
			this.passwordEncoder = passwordEncoder;
			return passwordEncoder;
		}

		private <T> T getBeanOrNull(Class<T> type) {
			try {
				return this.applicationContext.getBean(type);
			}
			catch (NoSuchBeanDefinitionException ex) {
				return null;
			}
		}

		@Override
		public String toString() {
			return getPasswordEncoder().toString();
		}

	}

}
