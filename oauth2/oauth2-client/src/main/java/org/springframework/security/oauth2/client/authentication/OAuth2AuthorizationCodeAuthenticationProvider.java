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

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.util.Assert;

/**
 * An implementation of an {@link AuthenticationProvider} for the OAuth 2.0 Authorization
 * Code Grant.
 *
 * authorization code grant 的 认证提供者实现 ...
 *
 * <p>
 * This {@link AuthenticationProvider} is responsible for authenticating an Authorization
 * Code credential with the Authorization Server's Token Endpoint and if valid, exchanging
 * it for an Access Token credential.
 *
 *
 * 这个认证提供器负责 认证一个授权码凭证(通过授权服务器的 token端点,并交换一个访问token 凭证) ..
 *
 * @author Joe Grandja
 * @since 5.1
 * @see OAuth2AuthorizationCodeAuthenticationToken
 * @see OAuth2AccessTokenResponseClient
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section
 * 4.1 Authorization Code Grant Flow</a>
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc6749#section-4.1.3">Section 4.1.3 Access Token
 * Request</a>
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc6749#section-4.1.4">Section 4.1.4 Access Token
 * Response</a>
 */
public class OAuth2AuthorizationCodeAuthenticationProvider implements AuthenticationProvider {

	private static final String INVALID_STATE_PARAMETER_ERROR_CODE = "invalid_state_parameter";

	private final OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;

	/**
	 * Constructs an {@code OAuth2AuthorizationCodeAuthenticationProvider} using the
	 * provided parameters.
	 * @param accessTokenResponseClient the client used for requesting the access token
	 * credential from the Token Endpoint
	 */
	public OAuth2AuthorizationCodeAuthenticationProvider(
			OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient) {
		Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
		this.accessTokenResponseClient = accessTokenResponseClient;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication = (OAuth2AuthorizationCodeAuthenticationToken) authentication;
		// 授权响应  ..
		OAuth2AuthorizationResponse authorizationResponse = authorizationCodeAuthentication.getAuthorizationExchange()
				.getAuthorizationResponse();

		// 如果有状态错误 ... 抛出异常 ...
		if (authorizationResponse.statusError()) {
			throw new OAuth2AuthorizationException(authorizationResponse.getError());
		}

		// 授权请求 ..
		OAuth2AuthorizationRequest authorizationRequest = authorizationCodeAuthentication.getAuthorizationExchange()
				.getAuthorizationRequest();

		// 两者状态不一致 ... 报错
		if (!authorizationResponse.getState().equals(authorizationRequest.getState())) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_STATE_PARAMETER_ERROR_CODE);
			throw new OAuth2AuthorizationException(oauth2Error);
		}

		// 访问 token 响应客户端获取 一个token 响应 ...
		OAuth2AccessTokenResponse accessTokenResponse = this.accessTokenResponseClient.getTokenResponse(
				new OAuth2AuthorizationCodeGrantRequest(authorizationCodeAuthentication.getClientRegistration(),
						authorizationCodeAuthentication.getAuthorizationExchange()));

		// 然后重新生成 ...
		OAuth2AuthorizationCodeAuthenticationToken authenticationResult = new OAuth2AuthorizationCodeAuthenticationToken(
				authorizationCodeAuthentication.getClientRegistration(),
				authorizationCodeAuthentication.getAuthorizationExchange(), accessTokenResponse.getAccessToken(),
				accessTokenResponse.getRefreshToken(), accessTokenResponse.getAdditionalParameters());
		authenticationResult.setDetails(authorizationCodeAuthentication.getDetails());
		return authenticationResult;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
