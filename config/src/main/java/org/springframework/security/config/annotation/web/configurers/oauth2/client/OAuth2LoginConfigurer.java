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

package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationProvider;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.CustomUserTypesOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.DelegatingOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

/**
 * An {@link AbstractHttpConfigurer} for OAuth 2.0 Login, which leverages the OAuth 2.0
 * Authorization Code Grant Flow.
 *
 * oauth 2.0 登录的抽象 http 配置器 ...
 * 通过oauth2.0 授权码授予流 ..
 *
 * <p>
 * OAuth 2.0 Login provides an application with the capability to have users log in by
 * using their existing account at an OAuth 2.0 or OpenID Connect 1.0 Provider.
 *
 * 	oauth2.0 登录让应用具有能力(使得用户能够通过它们存在的账户在 OAuth 2.0 或者 OpenId 连接 1.0 提供器上进行登录) ..
 * <p>
 * Defaults are provided for all configuration options with the only required
 * configuration being
 * {@link #clientRegistrationRepository(ClientRegistrationRepository)}. Alternatively, a
 * {@link ClientRegistrationRepository} {@code @Bean} may be registered instead.
 *
 * 所有的配置选项已经提供,仅仅需要配置 clientRegistrationRepository(ClientRegistrationRepository) ..
 * 除此之外, ClientRegistrationRepository @Bean 也可以注册(用于替代 ClientRegistrationRepository ) ..
 *
 *
 *  它会增加以下的安全过滤器 ...
 * <h2>Security Filters</h2>
 *
 * The following {@code Filter}'s are populated:
 *
 * <ul>
 * <li>{@link OAuth2AuthorizationRequestRedirectFilter}</li>
 * <li>{@link OAuth2LoginAuthenticationFilter}</li>
 * </ul>
 * 1. OAuth2AuthorizationRequestRedirectFilter 授权请求重定向过滤器 ..
 * 2. OAuth2LoginAuthenticationFilter 登录认证过滤器 ...
 *
 * 将会创建以下的共享对象 ...
 * <h2>Shared Objects Created</h2>
 *
 * The following shared objects are populated:
 *
 * <ul>
 * <li>{@link ClientRegistrationRepository} (required)</li>
 * <li>{@link OAuth2AuthorizedClientRepository} (optional)</li>
 * <li>{@link GrantedAuthoritiesMapper} (optional)</li>
 * </ul>
 *
 * 1. ClientRegistrationRepository(必须的) ...
 * 2. OAuth2AuthorizedClientRepository (可选的) ..
 * 3. GrantedAuthoritiesMapper (可选的) ...
 *
 * 被使用的共享对象:
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link ClientRegistrationRepository}</li>  管理/存储客户端注册的仓库 ...
 * <li>{@link OAuth2AuthorizedClientRepository}</li> 请求之间持久化OAuth2AuthorizeClient ...
 * <li>{@link GrantedAuthoritiesMapper}</li> 授予权限映射器 ...
 * <li>{@link DefaultLoginPageGeneratingFilter} - if {@link #loginPage(String)} is not
 * configured and {@code DefaultLoginPageGeneratingFilter} is available, then a default
 * login page will be made available</li>
 * </ul>
 *
 * 1. ClientRegistrationRepository
 * 2. OAuth2AuthorizedClientRepository
 * 3. GrantedAuthoritiesMapper
 * 4. DefaultLoginPageGeneratingFilter
 * 		如果loginPage(没有配置),并且 DefaultLoginPageGeneratingFilter是可用的,那么 默认的登录页面也变得可用 ...
 *
 * @author Joe Grandja
 * @author Kazuki Shimizu
 * @since 5.0
 * @see HttpSecurity#oauth2Login()
 * @see OAuth2AuthorizationRequestRedirectFilter
 * @see OAuth2LoginAuthenticationFilter
 * @see ClientRegistrationRepository
 * @see OAuth2AuthorizedClientRepository
 * @see AbstractAuthenticationFilterConfigurer
 */
public final class OAuth2LoginConfigurer<B extends HttpSecurityBuilder<B>>
		extends AbstractAuthenticationFilterConfigurer<B, OAuth2LoginConfigurer<B>, OAuth2LoginAuthenticationFilter> {

	// 授权端点
	private final AuthorizationEndpointConfig authorizationEndpointConfig = new AuthorizationEndpointConfig();

	/**
	 * access token 端点 ...
	 */
	private final TokenEndpointConfig tokenEndpointConfig = new TokenEndpointConfig();

	/**
	 * 重定向端点配置 ...
	 */
	private final RedirectionEndpointConfig redirectionEndpointConfig = new RedirectionEndpointConfig();

	/**
	 * 用户信息端点配置
	 */
	private final UserInfoEndpointConfig userInfoEndpointConfig = new UserInfoEndpointConfig();


	private String loginPage;

	// 登录的处理url(默认值)
	// 在这里也能看出来它使用的默认值是  OAuth2LoginAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI
	private String loginProcessingUrl = OAuth2LoginAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI;

	/**
	 * Sets the repository of client registrations.
	 * @param clientRegistrationRepository the repository of client registrations
	 * @return the {@link OAuth2LoginConfigurer} for further configuration
	 */
	public OAuth2LoginConfigurer<B> clientRegistrationRepository(
			ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		return this;
	}

	/**
	 * Sets the repository for authorized client(s).
	 * @param authorizedClientRepository the authorized client repository
	 * @return the {@link OAuth2LoginConfigurer} for further configuration
	 * @since 5.1
	 */
	public OAuth2LoginConfigurer<B> authorizedClientRepository(
			OAuth2AuthorizedClientRepository authorizedClientRepository) {
		Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
		this.getBuilder().setSharedObject(OAuth2AuthorizedClientRepository.class, authorizedClientRepository);
		return this;
	}

	/**
	 * Sets the service for authorized client(s).
	 * @param authorizedClientService the authorized client service
	 * @return the {@link OAuth2LoginConfigurer} for further configuration
	 */
	public OAuth2LoginConfigurer<B> authorizedClientService(OAuth2AuthorizedClientService authorizedClientService) {
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		this.authorizedClientRepository(
				new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService));
		return this;
	}

	@Override
	public OAuth2LoginConfigurer<B> loginPage(String loginPage) {
		Assert.hasText(loginPage, "loginPage cannot be empty");
		this.loginPage = loginPage;
		return this;
	}

	@Override
	public OAuth2LoginConfigurer<B> loginProcessingUrl(String loginProcessingUrl) {
		Assert.hasText(loginProcessingUrl, "loginProcessingUrl cannot be empty");
		this.loginProcessingUrl = loginProcessingUrl;
		return this;
	}

	/**
	 * Returns the {@link AuthorizationEndpointConfig} for configuring the Authorization
	 * Server's Authorization Endpoint.
	 * @return the {@link AuthorizationEndpointConfig}
	 */
	public AuthorizationEndpointConfig authorizationEndpoint() {
		return this.authorizationEndpointConfig;
	}

	/**
	 * Configures the Authorization Server's Authorization Endpoint.
	 * @param authorizationEndpointCustomizer the {@link Customizer} to provide more
	 * options for the {@link AuthorizationEndpointConfig}
	 * @return the {@link OAuth2LoginConfigurer} for further customizations
	 */
	public OAuth2LoginConfigurer<B> authorizationEndpoint(
			Customizer<AuthorizationEndpointConfig> authorizationEndpointCustomizer) {
		authorizationEndpointCustomizer.customize(this.authorizationEndpointConfig);
		return this;
	}

	/**
	 * Returns the {@link TokenEndpointConfig} for configuring the Authorization Server's
	 * Token Endpoint.
	 * @return the {@link TokenEndpointConfig}
	 */
	public TokenEndpointConfig tokenEndpoint() {
		return this.tokenEndpointConfig;
	}

	/**
	 * Configures the Authorization Server's Token Endpoint.
	 * @param tokenEndpointCustomizer the {@link Customizer} to provide more options for
	 * the {@link TokenEndpointConfig}
	 * @return the {@link OAuth2LoginConfigurer} for further customizations
	 * @throws Exception
	 */
	public OAuth2LoginConfigurer<B> tokenEndpoint(Customizer<TokenEndpointConfig> tokenEndpointCustomizer) {
		tokenEndpointCustomizer.customize(this.tokenEndpointConfig);
		return this;
	}

	/**
	 * Returns the {@link RedirectionEndpointConfig} for configuring the Client's
	 * Redirection Endpoint.
	 * @return the {@link RedirectionEndpointConfig}
	 */
	public RedirectionEndpointConfig redirectionEndpoint() {
		return this.redirectionEndpointConfig;
	}

	/**
	 * Configures the Client's Redirection Endpoint.
	 * @param redirectionEndpointCustomizer the {@link Customizer} to provide more options
	 * for the {@link RedirectionEndpointConfig}
	 * @return the {@link OAuth2LoginConfigurer} for further customizations
	 */
	public OAuth2LoginConfigurer<B> redirectionEndpoint(
			Customizer<RedirectionEndpointConfig> redirectionEndpointCustomizer) {
		redirectionEndpointCustomizer.customize(this.redirectionEndpointConfig);
		return this;
	}

	/**
	 * Returns the {@link UserInfoEndpointConfig} for configuring the Authorization
	 * Server's UserInfo Endpoint.
	 * @return the {@link UserInfoEndpointConfig}
	 */
	public UserInfoEndpointConfig userInfoEndpoint() {
		return this.userInfoEndpointConfig;
	}

	/**
	 * Configures the Authorization Server's UserInfo Endpoint.
	 * @param userInfoEndpointCustomizer the {@link Customizer} to provide more options
	 * for the {@link UserInfoEndpointConfig}
	 * @return the {@link OAuth2LoginConfigurer} for further customizations
	 */
	public OAuth2LoginConfigurer<B> userInfoEndpoint(Customizer<UserInfoEndpointConfig> userInfoEndpointCustomizer) {
		userInfoEndpointCustomizer.customize(this.userInfoEndpointConfig);
		return this;
	}

	@Override
	public void init(B http) throws Exception {

		// init phase ..

		// oauth2 授权登录入口 ..过滤器 .. 创建
		OAuth2LoginAuthenticationFilter authenticationFilter = new OAuth2LoginAuthenticationFilter(
				OAuth2ClientConfigurerUtils.getClientRegistrationRepository(this.getBuilder()),
				OAuth2ClientConfigurerUtils.getAuthorizedClientRepository(this.getBuilder()), this.loginProcessingUrl);

		// 然后并设置认证过滤器 ..
		this.setAuthenticationFilter(authenticationFilter);

		// 设置登录处理过滤器 ..
		super.loginProcessingUrl(this.loginProcessingUrl);

		// 表示自定义页面 ..
		if (this.loginPage != null) {
			// Set custom login page
			// 当设置了自定义的登录页面之后,认证端点也会发生变化
			super.loginPage(this.loginPage);
			super.init(http);
		}
		else {
			// 当没有自定义页面时,则获取登录Links
			Map<String, String> loginUrlToClientName = this.getLoginLinks();
			if (loginUrlToClientName.size() == 1) {
				// Setup auto-redirect to provider login page
				// when only 1 client is configured
				// 当仅仅只有一个客户端配置的时候,实现自动重定向到provider 登录页面 ...
				this.updateAuthenticationDefaults();
				this.updateAccessDefaults(http);

				String providerLoginPage = loginUrlToClientName.keySet().iterator().next();
				// 注册 认证端点 ...
				this.registerAuthenticationEntryPoint(http, this.getLoginEntryPoint(http, providerLoginPage));
			}
			else {
				// 否则调用 父类的init ..
				super.init(http);
			}
		}

		// 然后获取 访问token 响应client ..
		OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient = this.tokenEndpointConfig.accessTokenResponseClient;
		if (accessTokenResponseClient == null) {
			// 如果没有设置一个  .
			accessTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
		}
		// Oauth2UserService ..
		OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService = getOAuth2UserService();

		// 开始构建提供器 ...
		// 主要使用 userService,相比于 username/password,的情况下,它大致验证流程差不多 ...
		OAuth2LoginAuthenticationProvider oauth2LoginAuthenticationProvider = new OAuth2LoginAuthenticationProvider(
				accessTokenResponseClient, oauth2UserService);

		// 是否存在授予授权映射器
		GrantedAuthoritiesMapper userAuthoritiesMapper = this.getGrantedAuthoritiesMapper();

		if (userAuthoritiesMapper != null) {
			// 如果存在,则设置 ..
			oauth2LoginAuthenticationProvider.setAuthoritiesMapper(userAuthoritiesMapper);
		}
		// 认证提供器,增加 ..
		http.authenticationProvider(this.postProcess(oauth2LoginAuthenticationProvider));

		// oidc 认证提供器是否启动.也就是判断 JwtDecoder 是否存在 ...
		boolean oidcAuthenticationProviderEnabled = ClassUtils
				.isPresent("org.springframework.security.oauth2.jwt.JwtDecoder", this.getClass().getClassLoader());

		// 如果存在 ..
		if (oidcAuthenticationProviderEnabled) {
			// 获取 oidcUserService ..
			OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService = getOidcUserService();

			// 增加一个 Oidc 认证提供器 ..
			// 这两种是基于策略实现的 .
			OidcAuthorizationCodeAuthenticationProvider oidcAuthorizationCodeAuthenticationProvider = new OidcAuthorizationCodeAuthenticationProvider(
					accessTokenResponseClient, oidcUserService);

			JwtDecoderFactory<ClientRegistration> jwtDecoderFactory = this.getJwtDecoderFactoryBean();
			if (jwtDecoderFactory != null) {
				oidcAuthorizationCodeAuthenticationProvider.setJwtDecoderFactory(jwtDecoderFactory);
			}
			if (userAuthoritiesMapper != null) {
				oidcAuthorizationCodeAuthenticationProvider.setAuthoritiesMapper(userAuthoritiesMapper);
			}
			http.authenticationProvider(this.postProcess(oidcAuthorizationCodeAuthenticationProvider));
		}
		else {
			http.authenticationProvider(new OidcAuthenticationRequestChecker());
		}
		this.initDefaultLoginFilter(http);
	}

	@Override
	public void configure(B http) throws Exception {

		// 真正的配置 ...

		OAuth2AuthorizationRequestRedirectFilter authorizationRequestFilter;
		if (this.authorizationEndpointConfig.authorizationRequestResolver != null) {
			// 自定义的授权请求解析器
			authorizationRequestFilter = new OAuth2AuthorizationRequestRedirectFilter(
					this.authorizationEndpointConfig.authorizationRequestResolver);
		}
		else {
			// 否则 根据默认配置拼接 ..
			// 基于授权请求的base URI 进行处理 ..
			String authorizationRequestBaseUri = this.authorizationEndpointConfig.authorizationRequestBaseUri;
			if (authorizationRequestBaseUri == null) {
				// 没有配置  默认配置
				authorizationRequestBaseUri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
			}

			// 获取ClientRegistrationRepository ...
			// 并设定授权请求 base URI ..
			authorizationRequestFilter = new OAuth2AuthorizationRequestRedirectFilter(
					OAuth2ClientConfigurerUtils.getClientRegistrationRepository(this.getBuilder()),
					authorizationRequestBaseUri);
		}

		// 如果存在授权请求仓库 ..
		if (this.authorizationEndpointConfig.authorizationRequestRepository != null) {
			// 被用来映射对应的授权请求 ..
			authorizationRequestFilter
					.setAuthorizationRequestRepository(this.authorizationEndpointConfig.authorizationRequestRepository);
		}

		// 是否存在请求缓存..
		RequestCache requestCache = http.getSharedObject(RequestCache.class);
		// 如果有,则设置 ..
		if (requestCache != null) {
			authorizationRequestFilter.setRequestCache(requestCache);
		}

		http.addFilter(this.postProcess(authorizationRequestFilter));

		// 获取初始化好的 oauth2 登录认证过滤器 ..
		OAuth2LoginAuthenticationFilter authenticationFilter = this.getAuthenticationFilter();

		// 用来接收认证响应 ...
		if (this.redirectionEndpointConfig.authorizationResponseBaseUri != null) {
			authenticationFilter.setFilterProcessesUrl(this.redirectionEndpointConfig.authorizationResponseBaseUri);
		}
		// 设置授权请求仓库 ..
		if (this.authorizationEndpointConfig.authorizationRequestRepository != null) {
			authenticationFilter
					.setAuthorizationRequestRepository(this.authorizationEndpointConfig.authorizationRequestRepository);
		}
		super.configure(http);
	}

	@Override
	protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
		return new AntPathRequestMatcher(loginProcessingUrl);
	}

	@SuppressWarnings("unchecked")
	private JwtDecoderFactory<ClientRegistration> getJwtDecoderFactoryBean() {
		ResolvableType type = ResolvableType.forClassWithGenerics(JwtDecoderFactory.class, ClientRegistration.class);
		String[] names = this.getBuilder().getSharedObject(ApplicationContext.class).getBeanNamesForType(type);
		if (names.length > 1) {
			throw new NoUniqueBeanDefinitionException(type, names);
		}
		if (names.length == 1) {
			return (JwtDecoderFactory<ClientRegistration>) this.getBuilder().getSharedObject(ApplicationContext.class)
					.getBean(names[0]);
		}
		return null;
	}

	private GrantedAuthoritiesMapper getGrantedAuthoritiesMapper() {
		GrantedAuthoritiesMapper grantedAuthoritiesMapper = this.getBuilder()
				.getSharedObject(GrantedAuthoritiesMapper.class);
		if (grantedAuthoritiesMapper == null) {
			grantedAuthoritiesMapper = this.getGrantedAuthoritiesMapperBean();
			if (grantedAuthoritiesMapper != null) {
				this.getBuilder().setSharedObject(GrantedAuthoritiesMapper.class, grantedAuthoritiesMapper);
			}
		}
		return grantedAuthoritiesMapper;
	}

	private GrantedAuthoritiesMapper getGrantedAuthoritiesMapperBean() {
		Map<String, GrantedAuthoritiesMapper> grantedAuthoritiesMapperMap = BeanFactoryUtils
				.beansOfTypeIncludingAncestors(this.getBuilder().getSharedObject(ApplicationContext.class),
						GrantedAuthoritiesMapper.class);
		return (!grantedAuthoritiesMapperMap.isEmpty() ? grantedAuthoritiesMapperMap.values().iterator().next() : null);
	}

	private OAuth2UserService<OidcUserRequest, OidcUser> getOidcUserService() {
		if (this.userInfoEndpointConfig.oidcUserService != null) {
			return this.userInfoEndpointConfig.oidcUserService;
		}
		ResolvableType type = ResolvableType.forClassWithGenerics(OAuth2UserService.class, OidcUserRequest.class,
				OidcUser.class);
		OAuth2UserService<OidcUserRequest, OidcUser> bean = getBeanOrNull(type);
		return (bean != null) ? bean : new OidcUserService();
	}

	private OAuth2UserService<OAuth2UserRequest, OAuth2User> getOAuth2UserService() {
		// 如果存在配置 直接返回 ..
		if (this.userInfoEndpointConfig.userService != null) {
			return this.userInfoEndpointConfig.userService;
		}
		ResolvableType type = ResolvableType.forClassWithGenerics(OAuth2UserService.class, OAuth2UserRequest.class,
				OAuth2User.class);
		// 根据这个类型 从 bean 中返回 .. 如果有则返回 ..
		OAuth2UserService<OAuth2UserRequest, OAuth2User> bean = getBeanOrNull(type);
		if (bean != null) {
			return bean;
		}

		// 对于自定义的 OAuth2 情况,可能需要额外的 OAuth2User 类型 ..
		if (this.userInfoEndpointConfig.customUserTypes.isEmpty()) {
			//但是如果为空,则直接可以使用默认的 OAuth2UserService ..
			return new DefaultOAuth2UserService();
		}
		// 否则 存在自定义OauthUser的类型时 ..
		List<OAuth2UserService<OAuth2UserRequest, OAuth2User>> userServices = new ArrayList<>();

		userServices.add(new CustomUserTypesOAuth2UserService(this.userInfoEndpointConfig.customUserTypes));
		// 这是为了支持它默认的clientRegistration的 provider authorize ...
		userServices.add(new DefaultOAuth2UserService());
		return new DelegatingOAuth2UserService<>(userServices);
	}

	private <T> T getBeanOrNull(ResolvableType type) {
		ApplicationContext context = getBuilder().getSharedObject(ApplicationContext.class);
		if (context != null) {
			String[] names = context.getBeanNamesForType(type);
			if (names.length == 1) {
				return (T) context.getBean(names[0]);
			}
		}
		return null;
	}

	private void initDefaultLoginFilter(B http) {
		DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = http
				.getSharedObject(DefaultLoginPageGeneratingFilter.class);
		if (loginPageGeneratingFilter == null || this.isCustomLoginPage()) {
			return;
		}
		loginPageGeneratingFilter.setOauth2LoginEnabled(true);
		loginPageGeneratingFilter.setOauth2AuthenticationUrlToClientName(this.getLoginLinks());
		loginPageGeneratingFilter.setLoginPageUrl(this.getLoginPage());
		loginPageGeneratingFilter.setFailureUrl(this.getFailureUrl());
	}

	@SuppressWarnings("unchecked")
	private Map<String, String> getLoginLinks() {
		Iterable<ClientRegistration> clientRegistrations = null;
		// 授权从 builder中获取 ClientRegistrationRepository(这个是必须需要的) ..
		// 配置器上说明也告诉我们了 ..
		ClientRegistrationRepository clientRegistrationRepository = OAuth2ClientConfigurerUtils
				.getClientRegistrationRepository(this.getBuilder());
		// 将对应的实例 对应的ResolvableType 转换为 另一种 ResolvableType ..
		ResolvableType type = ResolvableType.forInstance(clientRegistrationRepository).as(Iterable.class);
		// 如果它不是NONE,并且 泛型参数对应了 ClientRegistration
		if (type != ResolvableType.NONE && ClientRegistration.class.isAssignableFrom(type.resolveGenerics()[0])) {
			// 直接强转 ..
			clientRegistrations = (Iterable<ClientRegistration>) clientRegistrationRepository;
		}
		// 否则 创建 一个空的map ..
		if (clientRegistrations == null) {
			return Collections.emptyMap();
		}
		//获取授权请求base URI ..
		String authorizationRequestBaseUri = (this.authorizationEndpointConfig.authorizationRequestBaseUri != null)
				? this.authorizationEndpointConfig.authorizationRequestBaseUri
				: OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;

		// 进行登录的连接(对应的Url 表示对应的 client 登录) ..
		Map<String, String> loginUrlToClientName = new HashMap<>();

		// 遍历 clientRegistrations ..判断授权授予类型是否是 授权码,如果是 ... 则拼接 ..
		clientRegistrations.forEach((registration) -> {
			if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(registration.getAuthorizationGrantType())) {
				String authorizationRequestUri = authorizationRequestBaseUri + "/" + registration.getRegistrationId();
				loginUrlToClientName.put(authorizationRequestUri, registration.getClientName());
			}
		});
		return loginUrlToClientName;
	}

	// 获取自动重定向登录url的 认证端点 ..
	private AuthenticationEntryPoint getLoginEntryPoint(B http, String providerLoginPage) {
		RequestMatcher loginPageMatcher = new AntPathRequestMatcher(this.getLoginPage());
		RequestMatcher faviconMatcher = new AntPathRequestMatcher("/favicon.ico");
		// 这是默认的 ..
		RequestMatcher defaultEntryPointMatcher = this.getAuthenticationEntryPointMatcher(http);

		// 这些应该是默认放行的 ...(例如login page / favicon.ico)
		RequestMatcher defaultLoginPageMatcher = new AndRequestMatcher(
				new OrRequestMatcher(loginPageMatcher, faviconMatcher), defaultEntryPointMatcher);

		RequestMatcher notXRequestedWith = new NegatedRequestMatcher(
				new RequestHeaderRequestMatcher("X-Requested-With", "XMLHttpRequest"));
		LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints = new LinkedHashMap<>();

		// 所以它需要匹配的是非登录页面 / 非 favicon.ico的非 ajax请求 ...
		entryPoints.put(new AndRequestMatcher(notXRequestedWith, new NegatedRequestMatcher(defaultLoginPageMatcher)),
				// 将它转发到这个认证端点,也就是提供者的登录url ..
				new LoginUrlAuthenticationEntryPoint(providerLoginPage));

		// 创建一个代理的认证端点 ..
		DelegatingAuthenticationEntryPoint loginEntryPoint = new DelegatingAuthenticationEntryPoint(entryPoints);
		// 如果没有匹配上任意一个,那么 使用默认的认证端点 ..
		// 同样你可以设置默认兜底的认证端点 ...
		loginEntryPoint.setDefaultEntryPoint(this.getAuthenticationEntryPoint());
		return loginEntryPoint;
	}

	/**
	 * Configuration options for the Authorization Server's Authorization Endpoint.
	 *
	 * 配置授权服务器的授权端点
	 */
	public final class AuthorizationEndpointConfig {

		/**
		 * 授权请求的基本uri ...
		 */
		private String authorizationRequestBaseUri;

		/**
		 * 授权服务请求解析器
		 */
		private OAuth2AuthorizationRequestResolver authorizationRequestResolver;

		/**
		 * 授权请求仓库 ..
		 */
		private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;

		private AuthorizationEndpointConfig() {
		}

		/**
		 * Sets the base {@code URI} used for authorization requests.
		 * @param authorizationRequestBaseUri the base {@code URI} used for authorization
		 * requests
		 * @return the {@link AuthorizationEndpointConfig} for further configuration
		 */
		public AuthorizationEndpointConfig baseUri(String authorizationRequestBaseUri) {
			Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
			this.authorizationRequestBaseUri = authorizationRequestBaseUri;
			return this;
		}

		/**
		 * Sets the resolver used for resolving {@link OAuth2AuthorizationRequest}'s.
		 * @param authorizationRequestResolver the resolver used for resolving
		 * {@link OAuth2AuthorizationRequest}'s
		 * @return the {@link AuthorizationEndpointConfig} for further configuration
		 * @since 5.1
		 */
		public AuthorizationEndpointConfig authorizationRequestResolver(
				OAuth2AuthorizationRequestResolver authorizationRequestResolver) {
			Assert.notNull(authorizationRequestResolver, "authorizationRequestResolver cannot be null");
			this.authorizationRequestResolver = authorizationRequestResolver;
			return this;
		}

		/**
		 * Sets the repository used for storing {@link OAuth2AuthorizationRequest}'s.
		 * @param authorizationRequestRepository the repository used for storing
		 * {@link OAuth2AuthorizationRequest}'s
		 * @return the {@link AuthorizationEndpointConfig} for further configuration
		 */
		public AuthorizationEndpointConfig authorizationRequestRepository(
				AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {
			Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
			this.authorizationRequestRepository = authorizationRequestRepository;
			return this;
		}

		/**
		 * Returns the {@link OAuth2LoginConfigurer} for further configuration.
		 * @return the {@link OAuth2LoginConfigurer}
		 */
		public OAuth2LoginConfigurer<B> and() {
			return OAuth2LoginConfigurer.this;
		}

	}

	/**
	 * Configuration options for the Authorization Server's Token Endpoint.
	 *
	 * 配置授权服务器的 token 端点 ...
	 */
	public final class TokenEndpointConfig {

		private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;

		private TokenEndpointConfig() {
		}

		/**
		 * Sets the client used for requesting the access token credential from the Token
		 * Endpoint.
		 * @param accessTokenResponseClient the client used for requesting the access
		 * token credential from the Token Endpoint
		 * @return the {@link TokenEndpointConfig} for further configuration
		 */
		public TokenEndpointConfig accessTokenResponseClient(
				OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient) {
			Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
			this.accessTokenResponseClient = accessTokenResponseClient;
			return this;
		}

		/**
		 * Returns the {@link OAuth2LoginConfigurer} for further configuration.
		 * @return the {@link OAuth2LoginConfigurer}
		 */
		public OAuth2LoginConfigurer<B> and() {
			return OAuth2LoginConfigurer.this;
		}

	}

	/**
	 * Configuration options for the Client's Redirection Endpoint.
	 */
	public final class RedirectionEndpointConfig {

		private String authorizationResponseBaseUri;

		private RedirectionEndpointConfig() {
		}

		/**
		 * Sets the {@code URI} where the authorization response will be processed.
		 * @param authorizationResponseBaseUri the {@code URI} where the authorization
		 * response will be processed
		 * @return the {@link RedirectionEndpointConfig} for further configuration
		 */
		public RedirectionEndpointConfig baseUri(String authorizationResponseBaseUri) {
			Assert.hasText(authorizationResponseBaseUri, "authorizationResponseBaseUri cannot be empty");
			this.authorizationResponseBaseUri = authorizationResponseBaseUri;
			return this;
		}

		/**
		 * Returns the {@link OAuth2LoginConfigurer} for further configuration.
		 * @return the {@link OAuth2LoginConfigurer}
		 */
		public OAuth2LoginConfigurer<B> and() {
			return OAuth2LoginConfigurer.this;
		}

	}

	/**
	 * Configuration options for the Authorization Server's UserInfo Endpoint.
	 */
	public final class UserInfoEndpointConfig {

		// 如果我们配置了如何进行 通过token 访问一个用户信息 ..
		private OAuth2UserService<OAuth2UserRequest, OAuth2User> userService;

		// 如果我们配置了如何通过 open connect id 访问 一个用户信息 ...
		private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService;

		private Map<String, Class<? extends OAuth2User>> customUserTypes = new HashMap<>();

		private UserInfoEndpointConfig() {
		}

		/**
		 * Sets the OAuth 2.0 service used for obtaining the user attributes of the
		 * End-User from the UserInfo Endpoint.
		 * @param userService the OAuth 2.0 service used for obtaining the user attributes
		 * of the End-User from the UserInfo Endpoint
		 * @return the {@link UserInfoEndpointConfig} for further configuration
		 */
		public UserInfoEndpointConfig userService(OAuth2UserService<OAuth2UserRequest, OAuth2User> userService) {
			Assert.notNull(userService, "userService cannot be null");
			this.userService = userService;
			return this;
		}

		/**
		 * Sets the OpenID Connect 1.0 service used for obtaining the user attributes of
		 * the End-User from the UserInfo Endpoint.
		 * @param oidcUserService the OpenID Connect 1.0 service used for obtaining the
		 * user attributes of the End-User from the UserInfo Endpoint
		 * @return the {@link UserInfoEndpointConfig} for further configuration
		 */
		public UserInfoEndpointConfig oidcUserService(OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService) {
			Assert.notNull(oidcUserService, "oidcUserService cannot be null");
			this.oidcUserService = oidcUserService;
			return this;
		}

		/**
		 * Sets a custom {@link OAuth2User} type and associates it to the provided client
		 * {@link ClientRegistration#getRegistrationId() registration identifier}.
		 * @param customUserType a custom {@link OAuth2User} type
		 * @param clientRegistrationId the client registration identifier
		 * @return the {@link UserInfoEndpointConfig} for further configuration
		 * @deprecated See {@link CustomUserTypesOAuth2UserService} for alternative usage.
		 */
		@Deprecated
		public UserInfoEndpointConfig customUserType(Class<? extends OAuth2User> customUserType,
				String clientRegistrationId) {
			Assert.notNull(customUserType, "customUserType cannot be null");
			Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
			this.customUserTypes.put(clientRegistrationId, customUserType);
			return this;
		}

		/**
		 * Sets the {@link GrantedAuthoritiesMapper} used for mapping
		 * {@link OAuth2User#getAuthorities()}.
		 * @param userAuthoritiesMapper the {@link GrantedAuthoritiesMapper} used for
		 * mapping the user's authorities
		 * @return the {@link UserInfoEndpointConfig} for further configuration
		 */
		public UserInfoEndpointConfig userAuthoritiesMapper(GrantedAuthoritiesMapper userAuthoritiesMapper) {
			Assert.notNull(userAuthoritiesMapper, "userAuthoritiesMapper cannot be null");
			OAuth2LoginConfigurer.this.getBuilder().setSharedObject(GrantedAuthoritiesMapper.class,
					userAuthoritiesMapper);
			return this;
		}

		/**
		 * Returns the {@link OAuth2LoginConfigurer} for further configuration.
		 * @return the {@link OAuth2LoginConfigurer}
		 */
		public OAuth2LoginConfigurer<B> and() {
			return OAuth2LoginConfigurer.this;
		}

	}

	// 如果存在 oidc ,直接抛出异常,不支持 ... 需要添加依赖 ..
	private static class OidcAuthenticationRequestChecker implements AuthenticationProvider {

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			OAuth2LoginAuthenticationToken authorizationCodeAuthentication = (OAuth2LoginAuthenticationToken) authentication;
			OAuth2AuthorizationRequest authorizationRequest = authorizationCodeAuthentication.getAuthorizationExchange()
					.getAuthorizationRequest();
			if (authorizationRequest.getScopes().contains(OidcScopes.OPENID)) {
				// Section 3.1.2.1 Authentication Request -
				// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest scope
				// REQUIRED. OpenID Connect requests MUST contain the "openid" scope
				// value.
				OAuth2Error oauth2Error = new OAuth2Error("oidc_provider_not_configured",
						"An OpenID Connect Authentication Provider has not been configured. "
								+ "Check to ensure you include the dependency 'spring-security-oauth2-jose'.",
						null);
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
			}
			return null;
		}

		@Override
		public boolean supports(Class<?> authentication) {
			return OAuth2LoginAuthenticationToken.class.isAssignableFrom(authentication);
		}

	}

}
