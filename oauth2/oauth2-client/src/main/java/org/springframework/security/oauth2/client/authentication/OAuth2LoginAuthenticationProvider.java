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

package org.springframework.security.oauth2.client.authentication;

import java.util.Collection;
import java.util.Map;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.Assert;

/**
 * An implementation of an {@link AuthenticationProvider} for OAuth 2.0 Login, which
 * leverages the OAuth 2.0 Authorization Code Grant Flow.
 *
 * 这个提供者实现,  进行oauth2 登录,它利用了oauth2.0 授权码授予流 ...
 *
 * This {@link AuthenticationProvider} is responsible for authenticating an Authorization
 * Code credential with the Authorization Server's Token Endpoint and if valid, exchanging
 * it for an Access Token credential.
 *
 * 这个认证提供器 负责认证一个授权码凭证(通过授权服务器的 token 认证端点,如果有效,交换访问 token 凭证) ...
 * <p>
 * It will also obtain the user attributes of the End-User (Resource Owner) from the
 * UserInfo Endpoint using an {@link OAuth2UserService}, which will create a
 * {@code Principal} in the form of an {@link OAuth2User}. The {@code OAuth2User} is then
 * associated to the {@link OAuth2LoginAuthenticationToken} to complete the
 * authentication.
 *
 * 它使用OAuth2UserService 从 用户端点中获取最终用户(资源拥有者)的用户属性 ....
 * 它会创建一个身份(形式为 OAuth2User) ... 这个user 会关联到 OAuth2LoginAuthenticationToken 去完成认证 ...
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2LoginAuthenticationToken
 * @see OAuth2AccessTokenResponseClient
 * @see OAuth2UserService
 * @see OAuth2User
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section
 * 4.1 Authorization Code Grant Flow</a>
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc6749#section-4.1.3">Section 4.1.3 Access Token
 * Request</a>
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc6749#section-4.1.4">Section 4.1.4 Access Token
 * Response</a>
 */
public class OAuth2LoginAuthenticationProvider implements AuthenticationProvider {

	// 然后它将代理到 授权码认证提供器 ...
	private final OAuth2AuthorizationCodeAuthenticationProvider authorizationCodeAuthenticationProvider;

	// user request -> user ..(这是最后一步)....
	private final OAuth2UserService<OAuth2UserRequest, OAuth2User> userService;

	// 授予认证映射 ...
	private GrantedAuthoritiesMapper authoritiesMapper = ((authorities) -> authorities);

	/**
	 * Constructs an {@code OAuth2LoginAuthenticationProvider} using the provided
	 * parameters.
	 * @param accessTokenResponseClient the client used for requesting the access token
	 * credential from the Token Endpoint
	 * @param userService the service used for obtaining the user attributes of the
	 * End-User from the UserInfo Endpoint
	 */
	public OAuth2LoginAuthenticationProvider(
			OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient,
			OAuth2UserService<OAuth2UserRequest, OAuth2User> userService) {
		Assert.notNull(userService, "userService cannot be null");
		this.authorizationCodeAuthenticationProvider = new OAuth2AuthorizationCodeAuthenticationProvider(
				accessTokenResponseClient);
		this.userService = userService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		// 开始验证 ....
		OAuth2LoginAuthenticationToken loginAuthenticationToken = (OAuth2LoginAuthenticationToken) authentication;
		// Section 3.1.2.1 Authentication Request -
		// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest scope
		// REQUIRED. OpenID Connect requests MUST contain the "openid" scope value.
		// 如果是 openid ... 让 OidcAuthorizationCodeAuthenticationProvider 处理 ...
		if (loginAuthenticationToken.getAuthorizationExchange().getAuthorizationRequest().getScopes()
				.contains("openid")) {
			// This is an OpenID Connect Authentication Request so return null
			// and let OidcAuthorizationCodeAuthenticationProvider handle it instead
			return null;
		}
		OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthenticationToken;

		// 然后根据授权码认证提供器进行认证 ...
		try {
			authorizationCodeAuthenticationToken = (OAuth2AuthorizationCodeAuthenticationToken) this.authorizationCodeAuthenticationProvider
					.authenticate(new OAuth2AuthorizationCodeAuthenticationToken(
							loginAuthenticationToken.getClientRegistration(),
							loginAuthenticationToken.getAuthorizationExchange()));
		}
		catch (OAuth2AuthorizationException ex) {
			OAuth2Error oauth2Error = ex.getError();
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), ex);
		}

		// 如果认证成功,获取访问 Token ...
		OAuth2AccessToken accessToken = authorizationCodeAuthenticationToken.getAccessToken();
		// 获取额外的参数 ...
		Map<String, Object> additionalParameters = authorizationCodeAuthenticationToken.getAdditionalParameters();
		// 通过用户服务(也就是现在拿到了AccessToken,如何获取用户并映射 权限交给我们用户处理) ...
		OAuth2User oauth2User = this.userService.loadUser(new OAuth2UserRequest(
				loginAuthenticationToken.getClientRegistration(), accessToken, additionalParameters));
		// 用户拿到了,通过 GrantedAuthoritiesMapper 进行权限映射 ...
		Collection<? extends GrantedAuthority> mappedAuthorities = this.authoritiesMapper
				.mapAuthorities(oauth2User.getAuthorities());
		// 然后重新创建 OAuth2LoginAuthenticationToken
		OAuth2LoginAuthenticationToken authenticationResult = new OAuth2LoginAuthenticationToken(
				loginAuthenticationToken.getClientRegistration(), loginAuthenticationToken.getAuthorizationExchange(),
				oauth2User, mappedAuthorities, accessToken, authorizationCodeAuthenticationToken.getRefreshToken());
		authenticationResult.setDetails(loginAuthenticationToken.getDetails());
		return authenticationResult;
	}

	/**
	 * Sets the {@link GrantedAuthoritiesMapper} used for mapping
	 * {@link OAuth2User#getAuthorities()} to a new set of authorities which will be
	 * associated to the {@link OAuth2LoginAuthenticationToken}.
	 * @param authoritiesMapper the {@link GrantedAuthoritiesMapper} used for mapping the
	 * user's authorities
	 */
	public final void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		Assert.notNull(authoritiesMapper, "authoritiesMapper cannot be null");
		this.authoritiesMapper = authoritiesMapper;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2LoginAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
