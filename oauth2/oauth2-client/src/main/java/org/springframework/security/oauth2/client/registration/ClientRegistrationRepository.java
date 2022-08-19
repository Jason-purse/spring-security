/*
 * Copyright 2002-2017 the original author or authors.
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

package org.springframework.security.oauth2.client.registration;

/**
 * A repository for OAuth 2.0 / OpenID Connect 1.0 {@link ClientRegistration}(s).
 *
 * <p>
 * <b>NOTE:</b> Client registration information is ultimately stored and owned by the
 * associated Authorization Server. Therefore, this repository provides the capability to
 * store a sub-set copy of the <i>primary</i> client registration information externally
 * from the Authorization Server.
 *
 * 一个 OAuth 2.0 / OpenId Connect 1.0 ClientRegistration的仓库
 *
 * 注意:  客户端注册 信息通常由 相关的授权服务器存储并所属 ...
 * 因此 这个仓库提供了一种能力去存储主要来自于外部授权服务器的子集 客户端注册信息 ...
 *
 * @author Joe Grandja
 * @since 5.0
 * @see ClientRegistration
 */
public interface ClientRegistrationRepository {

	/**
	 * Returns the client registration identified by the provided {@code registrationId},
	 * or {@code null} if not found.
	 * @param registrationId the registration identifier
	 * @return the {@link ClientRegistration} if found, otherwise {@code null}
	 */
	ClientRegistration findByRegistrationId(String registrationId);

}
