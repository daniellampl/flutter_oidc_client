import 'package:flutter/services.dart';
import 'package:flutter_appauth/flutter_appauth.dart';
import 'package:oidc_client/oidc_client.dart';

/// Specifies how the Authorization Server displays the authentication and
/// consent user interface pages to the End-User
enum OIDCDisplayValue {
  /// The Authorization Server SHOULD display the authentication and consent UI
  /// consistent with a full User Agent page view. If the display parameter is
  /// not specified, this is the default display mode.
  page,

  /// The Authorization Server SHOULD display the authentication and consent UI
  /// consistent with a popup User Agent window. The popup User Agent window
  /// should be of an appropriate size for a login-focused dialog and should not
  ///  obscure the entire window that it is popping up over.
  popup,

  /// The Authorization Server SHOULD display the authentication and consent UI
  /// consistent with a device that leverages a touch interface.
  touch,

  /// The Authorization Server SHOULD display the authentication and consent UI
  /// consistent with a "feature phone" type display
  wap,
}

/// Specifies whether the Authorization Server prompts the End-User for
/// reauthentication and consent.
enum OIDCPromptValue {
  /// The Authorization Server MUST NOT display any authentication or consent
  /// user interface pages. An error is returned if an End-User is not already
  /// authenticated or the Client does not have pre-configured consent for the
  /// requested Claims or does not fulfill other conditions for processing the
  /// request.
  none,

  /// The Authorization Server SHOULD prompt the End-User for reauthentication.
  login,

  /// The Authorization Server SHOULD prompt the End-User for consent before
  /// returning information to the Client.
  consent,

  /// The Authorization Server SHOULD prompt the End-User to select a user
  /// account. This enables an End-User who has multiple accounts at the
  /// Authorization Server to select amongst the multiple accounts that they
  /// might have current sessions for.
  selectAccount,
}

/// {@template oidc_token}
///
/// {@endtemplate}
class OIDCToken {
  /// {@macro oidc_token}
  const OIDCToken({
    required this.accessToken,
    required this.refreshToken,
    required this.idToken,
    required this.tokenType,
    this.accessTokenExpirationDateTime,
    this.scopes,
  });

  final String accessToken;
  final String refreshToken;
  final String idToken;
  final String tokenType;
  final DateTime? accessTokenExpirationDateTime;
  final List<String>? scopes;
}

/// {@template oidc_client_config}
///
/// {@endtemplate}
class OIDCClientConfig {
  /// {@macro oidc_client_config}
  const OIDCClientConfig({
    required this.clientId,
    required this.discoveryUrl,
    required this.redirectUrl,
    this.scope = const [],
  });

  final String clientId;

  final String redirectUrl;

  final String discoveryUrl;

  final List<String> scope;
}

/// {@template authorization_result}
///
/// {@endtemplate}
class AuthorizationResult {
  /// {@macro authorization_result}
  const AuthorizationResult({
    required this.authorizationCode,
    this.userInfo,
  });

  final String authorizationCode;
  final Map<String, dynamic>? userInfo;
}

/// {@template oidc_client}
///
/// {@endtemplate}
class OIDCClient {
  /// {@macro oidc_client}
  OIDCClient({
    required this.config,
    FlutterAppAuth? appAuth,
  }) : _appAuth = appAuth ?? FlutterAppAuth();

  final OIDCClientConfig config;

  final FlutterAppAuth _appAuth;

  ///
  Future<AuthorizationResult> authorize({
    List<String>? scope,
    String? nonce,
    OIDCDisplayValue? display,
    List<OIDCPromptValue>? prompt,
    int? maxAge,
    List<String>? uiLocales,
    String? idTokenHint,
    String? loginHint,
    List<String>? acrValues,
    Map<String, String>? parameters,
  }) async {
    try {
      final response = await _appAuth.authorize(
        AuthorizationRequest(
          config.clientId,
          config.redirectUrl,
          discoveryUrl: config.discoveryUrl,
          scopes: _transformScopes(scope ?? config.scope),
          promptValues: prompt != null
              ? prompt.map(_promptValueToString).toSet().toList()
              : [],
          loginHint: loginHint,
          additionalParameters: _buildAdditionalParameters(
            acrValues: acrValues,
            display: display,
            idTokenHint: idTokenHint,
            maxAge: maxAge,
            nonce: nonce,
            parameters: parameters,
            uiLocales: uiLocales,
          ),
        ),
      );
      if (response == null || response.authorizationCode == null) {
        throw const AuthorizeException(
          message: 'No authorization code received from authorization server!',
          errorCode: AuthorizeErrorCode.noAuthorizationCodeReceived,
        );
      }

      return AuthorizationResult(
        authorizationCode: response.authorizationCode!,
      );
    } on PlatformException catch (e) {
      throw AuthorizeException(
        message: e.message,
      );
    }
  }

  ///
  Future<OIDCToken> authenticate({
    List<String>? scope,
    String? nonce,
    OIDCDisplayValue? display,
    List<OIDCPromptValue>? prompt,
    int? maxAge,
    List<String>? uiLocales,
    String? idTokenHint,
    String? loginHint,
    List<String>? acrValues,
    Map<String, String>? parameters,
  }) async {
    try {
      final tokenResponse = await _appAuth.authorizeAndExchangeCode(
        AuthorizationTokenRequest(
          config.clientId,
          config.redirectUrl,
          discoveryUrl: config.discoveryUrl,
          scopes: _transformScopes(scope ?? config.scope),
          promptValues: prompt != null
              ? prompt.map(_promptValueToString).toSet().toList()
              : [],
          loginHint: loginHint,
          additionalParameters: _buildAdditionalParameters(
            acrValues: acrValues,
            display: display,
            idTokenHint: idTokenHint,
            maxAge: maxAge,
            nonce: nonce,
            parameters: parameters,
            uiLocales: uiLocales,
          ),
        ),
      );

      if (tokenResponse == null) {
        throw const AuthenticationFlowException(
          code: AuthenticationFlowErrorCode.noTokenReceived,
          message: 'No token response received!',
        );
      }

      return _mapTokenResponseToOIDCToken(tokenResponse);
    } on PlatformException catch (e) {
      throw AuthenticationFlowException.fromPlatformException(e);
    }
  }

  ///
  Future<OIDCToken> exchangeToken({
    required String subjectToken,
    required String subjectTokenType,
    String grantType = OIDCGrantType.tokenExchange,
    List<String>? scope,
    Map<String, String>? additionalParameters,
  }) async {
    final parameters = <String, String>{
      'subject_token': subjectToken,
      'subject_token_type': subjectTokenType,
    };

    if (additionalParameters != null) {
      parameters.addAll(additionalParameters);
    }

    try {
      final tokenResponse = await _appAuth.token(
        TokenRequest(
          config.clientId,
          config.redirectUrl,
          discoveryUrl: config.discoveryUrl,
          scopes: _transformScopes(scope ?? config.scope),
          grantType: grantType,
          additionalParameters: parameters,
        ),
      );

      if (tokenResponse == null) {
        throw const AuthenticationFlowException(
          code: AuthenticationFlowErrorCode.noTokenReceived,
          message: 'No token response received!',
        );
      }

      return _mapTokenResponseToOIDCToken(tokenResponse);
    } on PlatformException catch (e) {
      throw AuthenticationFlowException.fromPlatformException(e);
    }
  }

  ///
  Future<OIDCToken> refreshToken({
    required String refreshToken,
    String grantType = GrantType.refreshToken,
  }) async {
    try {
      final tokenResponse = await _appAuth.token(
        TokenRequest(
          config.clientId,
          config.redirectUrl,
          refreshToken: refreshToken,
          discoveryUrl: config.discoveryUrl,
          grantType: grantType,
        ),
      );

      if (tokenResponse == null) {
        throw const AuthenticationFlowException(
          code: AuthenticationFlowErrorCode.noTokenReceived,
          message: 'No token response received!',
        );
      }
      return _mapTokenResponseToOIDCToken(tokenResponse);
    } on PlatformException catch (e) {
      throw AuthenticationFlowException.fromPlatformException(e);
    }
  }

  String _displayValueToString(OIDCDisplayValue display) {
    switch (display) {
      case OIDCDisplayValue.page:
        return 'page';
      case OIDCDisplayValue.popup:
        return 'popup';
      case OIDCDisplayValue.touch:
        return 'touch';
      case OIDCDisplayValue.wap:
        return 'wap';
    }
  }

  String _promptValueToString(OIDCPromptValue prompt) {
    switch (prompt) {
      case OIDCPromptValue.none:
        return 'none';
      case OIDCPromptValue.login:
        return 'login';
      case OIDCPromptValue.consent:
        return 'consent';
      case OIDCPromptValue.selectAccount:
        return 'select_account';
    }
  }

  OIDCToken _mapTokenResponseToOIDCToken(TokenResponse response) {
    return OIDCToken(
      accessToken: response.accessToken!,
      refreshToken: response.refreshToken!,
      tokenType: response.tokenType!,
      idToken: response.idToken!,
      accessTokenExpirationDateTime: response.accessTokenExpirationDateTime,
      scopes: response.scopes,
    );
  }

  List<String> _transformScopes(List<String>? scopes) {
    final result = <String>[];

    if (scopes != null) {
      result.addAll(scopes);
    }

    if (!result.contains('openid')) {
      result.add('openid');
    }

    return result.toSet().toList();
  }

  Map<String, String> _buildAdditionalParameters({
    String? nonce,
    OIDCDisplayValue? display,
    int? maxAge,
    List<String>? uiLocales,
    String? idTokenHint,
    List<String>? acrValues,
    Map<String, String>? parameters,
  }) {
    final additionalParameters = <String, String>{};

    if (parameters != null && parameters.isNotEmpty) {
      additionalParameters.addAll(parameters);
    }

    if (nonce != null) {
      additionalParameters['nonce'] = nonce;
    }

    if (display != null) {
      additionalParameters['display'] = _displayValueToString(display);
    }

    if (maxAge != null) {
      additionalParameters['max_age'] = maxAge.toString();
    }

    if (uiLocales != null && uiLocales.isNotEmpty) {
      additionalParameters['ui_locales'] = uiLocales.join(' ');
    }

    if (idTokenHint != null) {
      additionalParameters['id_token_hint'] = idTokenHint;
    }

    if (acrValues != null && acrValues.isNotEmpty) {
      additionalParameters['acr_values'] = acrValues.join(' ');
    }

    return additionalParameters;
  }
}
