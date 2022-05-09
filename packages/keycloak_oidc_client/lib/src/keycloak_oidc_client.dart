import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:native_authorization/native_authorization.dart';
import 'package:oidc_client/oidc_client.dart';

const _kGoogleTokenExchangeSubjectIssuer = 'google';
const _kAppleTokenExchangeSubjectIssuer = 'apple';
const _kAppleSubjectTokenType = 'apple-authz-code';

const _kIdentityProviderHintParam = 'kc_idp_hint';

const _kGoogleIdpHint = 'google';
const _kAppleIdpHint = 'apple';
const _kFacebookIdpHint = 'facebook';

/// Defines which identity provider Keycloak should use to authenticate the
/// user.
enum KeycloakIdentityProvider {
  /// Indicates that Keycloak uses Facebook as identity provider.
  google,

  /// Indicates that Keycloak uses Apple as identity provider.
  apple,

  /// Indicates that Keycloak uses Faceboook as identity provider.
  facebook,
}

/// Describes how the authentication UI should be displayed to the user.
enum DisplayBehavior {
  /// The user gets redirected to the browser to display the authentication UI
  /// of the Authorization Server.
  browser,

  /// The native authentication UI gets used for authentication.
  ///
  /// This will result in exchanging the received authorization code or an
  /// access token (of the external identity provider) with an [OIDCToken] from
  /// the Azuthorization Server.
  nativeIfPossible,
}

/// {@template keycloak_oidc_client}
/// An OIDC client that interacts with a Keycloak authentication server.
/// {@endtemplate}
class KeycloakOIDCClient extends OIDCClient with OIDCClientMixin {
  /// {@macro keycloak_oidc_client}
  KeycloakOIDCClient({
    required OIDCClientConfig config,
    NativeAuthorization? nativeAuthorization,
  })  : _nativeAuthorization = nativeAuthorization ?? NativeAuthorization(),
        super(config: config);

  final NativeAuthorization _nativeAuthorization;

  ///
  Future<OIDCToken> authenticateProvider({
    KeycloakIdentityProvider? identityProvider,
    DisplayBehavior displayBehavior = DisplayBehavior.browser,
    List<String>? scopes,
    List<OIDCPromptValue>? prompt,
    String? appIdentifier,
  }) async {
    if (displayBehavior == DisplayBehavior.nativeIfPossible) {
      if (identityProvider == KeycloakIdentityProvider.apple &&
          (Platform.isIOS || Platform.isMacOS)) {
        assert(
          appIdentifier != null,
          '"appIdentifier" must not be `null` for apple token exchange!',
        );

        final appleResult = await _nativeAuthorization.apple();

        return super.exchangeToken(
          subjectToken: appleResult.authorizationCode,
          subjectTokenType: _kAppleSubjectTokenType,
          scope: scopes,
          additionalParameters: {
            'subject_issuer': _kAppleTokenExchangeSubjectIssuer,
            'app_identifier': appIdentifier!,
            'user_profile': jsonEncode(appleResult.userInfo),
          },
        );
      } else if (identityProvider == KeycloakIdentityProvider.google &&
          Platform.isAndroid) {
        final googleAccessToken = await _nativeAuthorization.google();

        if (googleAccessToken == null) {
          throw const AuthorizeException(
            message: 'No access token received from Google sign in!',
            errorCode: AuthorizeErrorCode.noAuthorizationCodeReceived,
          );
        }

        return super.exchangeToken(
          subjectToken: googleAccessToken,
          subjectTokenType: OIDCSubjectTokenType.accessToken,
          scope: scopes,
          additionalParameters: {
            'subject_issuer': _kGoogleTokenExchangeSubjectIssuer,
          },
        );
      }
    }

    if (prompt != null && prompt.isNotEmpty) {
      assert(
        !prompt.contains(OIDCPromptValue.selectAccount),
        '"select_account" prompt is not supported by Keycloak!',
      );
    }

    final parameters = <String, String>{};
    final identityProviderHint = identityProvider != null
        ? _getIdentityProviderHint(identityProvider)
        : null;

    if (identityProviderHint != null) {
      parameters[_kIdentityProviderHintParam] = identityProviderHint;
    }

    return super.authenticate(
      scope: scopes,
      prompt: prompt,
      parameters: parameters,
    );
  }

  ///
  Future<void> logoutSilently({
    required String refreshToken,
    String? logoutEndpoint,
  }) async {
    try {
      logoutEndpoint ??=
          await super.fetchEndSessionUrlFromDiscoveryUrl(config.discoveryUrl);

      await http.post(
        Uri.parse(logoutEndpoint),
        body: {
          'client_id': config.clientId,
          'refresh_token': refreshToken,
        },
      );
    } catch (e) {
      throw LogoutFailedException();
    }
  }

  String? _getIdentityProviderHint(KeycloakIdentityProvider provider) {
    switch (provider) {
      case KeycloakIdentityProvider.google:
        return _kGoogleIdpHint;
      case KeycloakIdentityProvider.apple:
        return _kAppleIdpHint;
      case KeycloakIdentityProvider.facebook:
        return _kFacebookIdpHint;
    }
  }
}
