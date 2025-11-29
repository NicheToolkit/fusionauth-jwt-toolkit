
package io.github.nichetoolkit.fusionauth.oauth2.domain;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import io.github.nichetoolkit.fusionauth.jwt.json.Mapper;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * <code>AuthorizationServerMetaData</code>
 * <p>The authorization server meta data class.</p>
 * @author Cyan (snow22314@outlook.com)
 * @since Jdk17
 */
public class AuthorizationServerMetaData {
  /**
   * <code>authorization_endpoint</code>
   * {@link java.lang.String} <p>The <code>authorization_endpoint</code> field.</p>
   * @see java.lang.String
   */
  public String authorization_endpoint;

  /**
   * <code>code_challenge_methods_supported</code>
   * {@link java.util.List} <p>The <code>code_challenge_methods_supported</code> field.</p>
   * @see java.util.List
   */
  public List<String> code_challenge_methods_supported;

  /**
   * <code>grant_types_supported</code>
   * {@link java.util.List} <p>The <code>grant_types_supported</code> field.</p>
   * @see java.util.List
   */
  public List<String> grant_types_supported;

  /**
   * <code>introspection_endpoint</code>
   * {@link java.lang.String} <p>The <code>introspection_endpoint</code> field.</p>
   * @see java.lang.String
   */
  public String introspection_endpoint;

  /**
   * <code>introspection_endpoint_auth_methods_supported</code>
   * {@link java.util.List} <p>The <code>introspection_endpoint_auth_methods_supported</code> field.</p>
   * @see java.util.List
   */
  public List<String> introspection_endpoint_auth_methods_supported;

  /**
   * <code>introspection_endpoint_auth_signing_alg_values_supported</code>
   * {@link java.util.List} <p>The <code>introspection_endpoint_auth_signing_alg_values_supported</code> field.</p>
   * @see java.util.List
   */
  public List<String> introspection_endpoint_auth_signing_alg_values_supported;

  /**
   * <code>issuer</code>
   * {@link java.lang.String} <p>The <code>issuer</code> field.</p>
   * @see java.lang.String
   */
  public String issuer;

  /**
   * <code>jwks_uri</code>
   * {@link java.lang.String} <p>The <code>jwks_uri</code> field.</p>
   * @see java.lang.String
   */
  public String jwks_uri;

  /**
   * <code>op_policy_uri</code>
   * {@link java.lang.String} <p>The <code>op_policy_uri</code> field.</p>
   * @see java.lang.String
   */
  public String op_policy_uri;

  /**
   * <code>op_tos_uri</code>
   * {@link java.lang.String} <p>The <code>op_tos_uri</code> field.</p>
   * @see java.lang.String
   */
  public String op_tos_uri;

  /**
   * <code>otherClaims</code>
   * {@link java.util.Map} <p>The <code>otherClaims</code> field.</p>
   * @see java.util.Map
   * @see com.fasterxml.jackson.annotation.JsonAnySetter
   */
  @JsonAnySetter
  public Map<String, Object> otherClaims = new LinkedHashMap<>();

  /**
   * <code>registration_endpoint</code>
   * {@link java.lang.String} <p>The <code>registration_endpoint</code> field.</p>
   * @see java.lang.String
   */
  public String registration_endpoint;

  /**
   * <code>response_modes_supported</code>
   * {@link java.util.List} <p>The <code>response_modes_supported</code> field.</p>
   * @see java.util.List
   */
  public List<String> response_modes_supported;

  /**
   * <code>response_types_supported</code>
   * {@link java.util.List} <p>The <code>response_types_supported</code> field.</p>
   * @see java.util.List
   */
  public List<String> response_types_supported;

  /**
   * <code>revocation_endpoint</code>
   * {@link java.lang.String} <p>The <code>revocation_endpoint</code> field.</p>
   * @see java.lang.String
   */
  public String revocation_endpoint;

  /**
   * <code>revocation_endpoint_auth_methods_supported</code>
   * {@link java.util.List} <p>The <code>revocation_endpoint_auth_methods_supported</code> field.</p>
   * @see java.util.List
   */
  public List<String> revocation_endpoint_auth_methods_supported;

  /**
   * <code>revocation_endpoint_auth_signing_alg_values_supported</code>
   * {@link java.util.List} <p>The <code>revocation_endpoint_auth_signing_alg_values_supported</code> field.</p>
   * @see java.util.List
   */
  public List<String> revocation_endpoint_auth_signing_alg_values_supported;

  /**
   * <code>scopes_supported</code>
   * {@link java.util.List} <p>The <code>scopes_supported</code> field.</p>
   * @see java.util.List
   */
  public List<String> scopes_supported;

  /**
   * <code>service_documentation</code>
   * {@link java.lang.String} <p>The <code>service_documentation</code> field.</p>
   * @see java.lang.String
   */
  public String service_documentation;

  /**
   * <code>token_endpoint</code>
   * {@link java.lang.String} <p>The <code>token_endpoint</code> field.</p>
   * @see java.lang.String
   */
  public String token_endpoint;

  /**
   * <code>token_endpoint_auth_methods_supported</code>
   * {@link java.util.List} <p>The <code>token_endpoint_auth_methods_supported</code> field.</p>
   * @see java.util.List
   */
  public List<String> token_endpoint_auth_methods_supported;

  /**
   * <code>token_endpoint_auth_signing_alg_values_supported</code>
   * {@link java.util.List} <p>The <code>token_endpoint_auth_signing_alg_values_supported</code> field.</p>
   * @see java.util.List
   */
  public List<String> token_endpoint_auth_signing_alg_values_supported;

  /**
   * <code>ui_locales_supported</code>
   * {@link java.util.List} <p>The <code>ui_locales_supported</code> field.</p>
   * @see java.util.List
   */
  public List<String> ui_locales_supported;

  /**
   * <code>getOtherClaims</code>
   * <p>The get other claims getter method.</p>
   * @return {@link java.util.Map} <p>The get other claims return object is <code>Map</code> type.</p>
   * @see java.util.Map
   * @see com.fasterxml.jackson.annotation.JsonAnyGetter
   */
  @JsonAnyGetter
  public Map<String, Object> getOtherClaims() {
    return otherClaims;
  }

  @Override
  public String toString() {
    return new String(Mapper.prettyPrint(this));
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    AuthorizationServerMetaData metaData = (AuthorizationServerMetaData) o;
    return Objects.equals(authorization_endpoint, metaData.authorization_endpoint) && Objects.equals(code_challenge_methods_supported, metaData.code_challenge_methods_supported) && Objects.equals(grant_types_supported, metaData.grant_types_supported) && Objects.equals(introspection_endpoint, metaData.introspection_endpoint) && Objects.equals(introspection_endpoint_auth_methods_supported, metaData.introspection_endpoint_auth_methods_supported) && Objects.equals(introspection_endpoint_auth_signing_alg_values_supported, metaData.introspection_endpoint_auth_signing_alg_values_supported) && Objects.equals(issuer, metaData.issuer) && Objects.equals(jwks_uri, metaData.jwks_uri) && Objects.equals(op_policy_uri, metaData.op_policy_uri) && Objects.equals(op_tos_uri, metaData.op_tos_uri) && Objects.equals(otherClaims, metaData.otherClaims) && Objects.equals(registration_endpoint, metaData.registration_endpoint) && Objects.equals(response_modes_supported, metaData.response_modes_supported) && Objects.equals(response_types_supported, metaData.response_types_supported) && Objects.equals(revocation_endpoint, metaData.revocation_endpoint) && Objects.equals(revocation_endpoint_auth_methods_supported, metaData.revocation_endpoint_auth_methods_supported) && Objects.equals(revocation_endpoint_auth_signing_alg_values_supported, metaData.revocation_endpoint_auth_signing_alg_values_supported) && Objects.equals(scopes_supported, metaData.scopes_supported) && Objects.equals(service_documentation, metaData.service_documentation) && Objects.equals(token_endpoint, metaData.token_endpoint) && Objects.equals(token_endpoint_auth_methods_supported, metaData.token_endpoint_auth_methods_supported) && Objects.equals(token_endpoint_auth_signing_alg_values_supported, metaData.token_endpoint_auth_signing_alg_values_supported) && Objects.equals(ui_locales_supported, metaData.ui_locales_supported);
  }

  @Override
  public int hashCode() {
    return Objects.hash(authorization_endpoint, code_challenge_methods_supported, grant_types_supported, introspection_endpoint, introspection_endpoint_auth_methods_supported, introspection_endpoint_auth_signing_alg_values_supported, issuer, jwks_uri, op_policy_uri, op_tos_uri, otherClaims, registration_endpoint, response_modes_supported, response_types_supported, revocation_endpoint, revocation_endpoint_auth_methods_supported, revocation_endpoint_auth_signing_alg_values_supported, scopes_supported, service_documentation, token_endpoint, token_endpoint_auth_methods_supported, token_endpoint_auth_signing_alg_values_supported, ui_locales_supported);
  }
}
