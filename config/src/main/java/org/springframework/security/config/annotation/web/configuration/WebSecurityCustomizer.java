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

import org.springframework.security.config.annotation.web.builders.WebSecurity;

/**
 * Callback interface for customizing {@link WebSecurity}.
 *
 * Beans of this type will automatically be used by {@link WebSecurityConfiguration} to
 * customize {@link WebSecurity}.
 *
 * Example usage:
 *
 * <pre>
 * &#064;Bean
 * public WebSecurityCustomizer ignoringCustomizer() {
 * 	return (web) -&gt; web.ignoring().antMatchers("/ignore1", "/ignore2");
 * }
 * </pre>
 *
 * 直接单纯的为了定制WebSecurity的回调接口 ..
 * 因为这个类型的 bean 将会自动的被WebSecurityConfiguration 用来定制 WebSecurity ..
 * 就是单纯的定制 ...
 *
 * @author Eleftheria Stein
 * @since 5.4
 */
@FunctionalInterface
public interface WebSecurityCustomizer {

	/**
	 * Performs the customizations on {@link WebSecurity}.
	 * @param web the instance of {@link WebSecurity} to apply to customizations to
	 */
	void customize(WebSecurity web);

}
