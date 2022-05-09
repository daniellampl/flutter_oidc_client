class OIDCSubjectTokenType {
  ///Indicates that the token is an OAuth 2.0 access token issued by the given
  ///authorization server.
  static const String accessToken =
      'urn:ietf:params:oauth:token-type:access_token';

  ///Indicates that the token is an OAuth 2.0 refresh token issued by the given
  ///authorization server.
  static const String refreshToken =
      'urn:ietf:params:oauth:token-type:refresh_token';

  /// Indicates that the token is an ID Token.
  static const String idToken = 'urn:ietf:params:oauth:token-type:id_token';

  /// Indicates that the token is a base64url-encoded SAML 1.1 assertion.
  static const String saml1 = 'urn:ietf:params:oauth:token-type:saml1';

  /// Indicates that the token is a base64url-encoded SAML 2.0 assertion.
  static const String saml2 = 'urn:ietf:params:oauth:token-type:saml2';
}

class OIDCGrantType {
  static const String tokenExchange =
      'urn:ietf:params:oauth:grant-type:token-exchange';

  static const String refreshToken = 'refresh_token';
}
