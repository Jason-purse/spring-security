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

package org.springframework.security.oauth2.client.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationProvider;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * An implementation of an {@link AbstractAuthenticationProcessingFilter} for OAuth 2.0
 * Login.
 * 	AbstractAuthenticationProcessingFilter 的实现用来处理OAuth 2.0 登录 ...
 *
 * <p>
 * This authentication {@code Filter} handles the processing of an OAuth 2.0 Authorization
 * Response for the authorization code grant flow and delegates an
 * {@link OAuth2LoginAuthenticationToken} to the {@link AuthenticationManager} to log in
 * the End-User.
 *
 * 这个认证过滤器处理  OAuth 2.0 授权响应的过程(对于授权码授予流)
 * 并代理 OAuth2LoginAuthenticationToken 到AuthenticationManager 进行最终用户登录 ...
 *
 * <p>
 * The OAuth 2.0 Authorization Response is processed as follows:
 *
 * OAuth2.0 授权响应处理如下:
 * 1. 假设 最终用户(Resource Owner) 授权访问此客户端 ... 那么这个授权服务器将会追加 OAuth2ParameterNames#CODE 以及 STATE 到 REDIRECT_URI上(它由授权请求提供) ..
 * 并重定向到最终用户的用户代理 然后返回到此过滤器（这个客户端) ...
 * 2. 此过滤器将创建一个OAuth2LoginAuthenticationToken(通过接收到的OAuth2ParameterNames#CODE) 并代理到 AuthenticationManager 进行认证 ...
 * 3. 在成功认证之后, 一个OAuth2AuthenticationToken 将会被创建(代表最终用户身份)并使用 OAuth2AuthorizedClientRepository 关联到 OAuth2AuthorizedClient ...
 * 4. 最终,OAuth2AuthenticationToken 将被返回并最终存储到 SecurityContextRepository 去完成认证处理 ...
 * <ul>
 * <li>Assuming the End-User (Resource Owner) has granted access to the Client, the
 * Authorization Server will append the {@link OAuth2ParameterNames#CODE code} and
 * {@link OAuth2ParameterNames#STATE state} parameters to the
 * {@link OAuth2ParameterNames#REDIRECT_URI redirect_uri} (provided in the Authorization
 * Request) and redirect the End-User's user-agent back to this {@code Filter} (the
 * Client).</li>
 * <li>This {@code Filter} will then create an {@link OAuth2LoginAuthenticationToken} with
 * the {@link OAuth2ParameterNames#CODE code} received and delegate it to the
 * {@link AuthenticationManager} to authenticate.</li>
 * <li>Upon a successful authentication, an {@link OAuth2AuthenticationToken} is created
 * (representing the End-User {@code Principal}) and associated to the
 * {@link OAuth2AuthorizedClient Authorized Client} using the
 * {@link OAuth2AuthorizedClientRepository}.</li>
 * <li>Finally, the {@link OAuth2AuthenticationToken} is returned and ultimately stored in
 * the {@link SecurityContextRepository} to complete the authentication processing.</li>
 * </ul>
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AbstractAuthenticationProcessingFilter
 * @see OAuth2LoginAuthenticationToken
 * @see OAuth2AuthenticationToken
 * @see OAuth2LoginAuthenticationProvider
 * @see OAuth2AuthorizationRequest
 * @see OAuth2AuthorizationResponse
 * @see AuthorizationRequestRepository
 * @see OAuth2AuthorizationRequestRedirectFilter
 * @see ClientRegistrationRepository
 * @see OAuth2AuthorizedClient
 * @see OAuth2AuthorizedClientRepository
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section
 * 4.1 Authorization Code Grant</a>
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc6749#section-4.1.2">Section 4.1.2 Authorization
 * Response</a>
 *
 *
 * 也就是说此类是 OAuth2 登录授权的入口 ...
 */
public class OAuth2LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	/**
	 * The default {@code URI} where this {@code Filter} processes authentication
	 * requests.
	 */
	public static final String DEFAULT_FILTER_PROCESSES_URI = "/login/oauth2/code/*";

	private static final String AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE = "authorization_request_not_found";

	private static final String CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE = "client_registration_not_found";

	/**
	 * 客户端注册仓库 ...
	 *
	 * 我们是可以定制的 ... 默认是一个内存型的 ...
	 */
	private ClientRegistrationRepository clientRegistrationRepository;

	/**
	 * 已经授权的客户端仓库 ..
	 */
	private OAuth2AuthorizedClientRepository authorizedClientRepository;

	// 授权请求仓库 ..
	private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = new HttpSessionOAuth2AuthorizationRequestRepository();


	// 认证结果转换器 ..
	// 将一个OAuth2LoginAuthenticationToken 转换为 OAuth2AuthenticationToken ..
	private Converter<OAuth2LoginAuthenticationToken, OAuth2AuthenticationToken> authenticationResultConverter = this::createAuthenticationResult;

	/**
	 * Constructs an {@code OAuth2LoginAuthenticationFilter} using the provided
	 * parameters.
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClientService the authorized client service
	 */
	public OAuth2LoginAuthenticationFilter(ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientService authorizedClientService) {
		this(clientRegistrationRepository, authorizedClientService, DEFAULT_FILTER_PROCESSES_URI);
	}

	/**
	 * Constructs an {@code OAuth2LoginAuthenticationFilter} using the provided
	 * parameters.
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClientService the authorized client service
	 * @param filterProcessesUrl the {@code URI} where this {@code Filter} will process
	 * the authentication requests
	 */
	public OAuth2LoginAuthenticationFilter(ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientService authorizedClientService, String filterProcessesUrl) {
		this(clientRegistrationRepository,
				new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService),
				filterProcessesUrl);
	}

	/**
	 * Constructs an {@code OAuth2LoginAuthenticationFilter} using the provided
	 * parameters.
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClientRepository the authorized client repository
	 * @param filterProcessesUrl the {@code URI} where this {@code Filter} will process
	 * the authentication requests
	 * @since 5.1
	 */
	public OAuth2LoginAuthenticationFilter(ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository, String filterProcessesUrl) {
		super(filterProcessesUrl);
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizedClientRepository = authorizedClientRepository;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {


		MultiValueMap<String, String> params = OAuth2AuthorizationResponseUtils.toMultiMap(request.getParameterMap());

		if (!OAuth2AuthorizationResponseUtils.isAuthorizationResponse(params)) {
			OAuth2Error oauth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}

		// 授权响应回来之后,  根据授权请求仓库 获取响应对应的请求 ...
		OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestRepository
				.removeAuthorizationRequest(request, response);
		// 如果授权请求为空 ..
		if (authorizationRequest == null) {
			// 抛出异常 ...
			OAuth2Error oauth2Error = new OAuth2Error(AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}

		// 当响应拿到之后, 获取授权请求的 对应的provider 对应的registrationId ...
		String registrationId = authorizationRequest.getAttribute(OAuth2ParameterNames.REGISTRATION_ID);
		// 获取对应的客户端注册 ...
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);

		// 当 客户端Registration 为空,则表示 授权异常 ...
		if (clientRegistration == null) {
			OAuth2Error oauth2Error = new OAuth2Error(CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE,
					"Client Registration not found with Id: " + registrationId, null);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}

		// 如果一切正常 ...
		// @formatter:off
		String redirectUri = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
				.replaceQuery(null)
				.build()
				.toUriString();
		// @formatter:on
		// 尝试将参数以及重定向url 转换为 响应 ...
		OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponseUtils.convert(params,
				redirectUri);
		// 这个时候尝试为这个授权请求构建认证详情(认证的token的一些细节信息,例如请求来源,会话id信息)
		Object authenticationDetails = this.authenticationDetailsSource.buildDetails(request);

		// 于是构建一个OAuth2Login 认证token ...
		OAuth2LoginAuthenticationToken authenticationRequest = new OAuth2LoginAuthenticationToken(clientRegistration,
				new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));
		authenticationRequest.setDetails(authenticationDetails);

		// 然后开始认证,初始化授权码授予流 ...
		// 相当于进入了OAuth2....Provider
		OAuth2LoginAuthenticationToken authenticationResult = (OAuth2LoginAuthenticationToken) this
				.getAuthenticationManager().authenticate(authenticationRequest);

		// 最终认证结果完成之后 ...
		OAuth2AuthenticationToken oauth2Authentication = this.authenticationResultConverter
				.convert(authenticationResult);
		Assert.notNull(oauth2Authentication, "authentication result cannot be null");
		// 重新设置 details ..
		oauth2Authentication.setDetails(authenticationDetails);

		// 认证成功,创建一个授权完成的client ...(它主要包含三大内容, 第一个registration , 对应的principalName 映射到对应的访问 token,  以及刷新token ..
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				authenticationResult.getClientRegistration(), oauth2Authentication.getName(),
				authenticationResult.getAccessToken(), authenticationResult.getRefreshToken());

		// 然后保存到 授权完成的客户端仓库 ...
		this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, oauth2Authentication, request, response);
		return oauth2Authentication;
	}

	/**
	 * Sets the repository for stored {@link OAuth2AuthorizationRequest}'s.
	 * @param authorizationRequestRepository the repository for stored
	 * {@link OAuth2AuthorizationRequest}'s
	 */
	public final void setAuthorizationRequestRepository(
			AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {
		Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
		this.authorizationRequestRepository = authorizationRequestRepository;
	}

	/**
	 * Sets the converter responsible for converting from
	 * {@link OAuth2LoginAuthenticationToken} to {@link OAuth2AuthenticationToken}
	 * authentication result.
	 * @param authenticationResultConverter the converter for
	 * {@link OAuth2AuthenticationToken}'s
	 * @since 5.6
	 */
	public final void setAuthenticationResultConverter(
			Converter<OAuth2LoginAuthenticationToken, OAuth2AuthenticationToken> authenticationResultConverter) {
		Assert.notNull(authenticationResultConverter, "authenticationResultConverter cannot be null");
		this.authenticationResultConverter = authenticationResultConverter;
	}

	private OAuth2AuthenticationToken createAuthenticationResult(OAuth2LoginAuthenticationToken authenticationResult) {

		// 直接将对应的身份, 授权集合,registrationId 获取构建返回即可 ..
		return new OAuth2AuthenticationToken(authenticationResult.getPrincipal(), authenticationResult.getAuthorities(),
				authenticationResult.getClientRegistration().getRegistrationId());
	}

}
