import 'dart:convert';

import 'package:http/http.dart' as http;
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

  /// Indicates that Keycloak uses Apple as identity provider.
  facebook,
}

/// {@template keycloak_oidc_client}
/// An OIDC client that interacts with a Keycloak authentication server.
/// {@endtemplate}
class KeycloakOIDCClient extends OIDCClient with OIDCClientMixin {
  /// {@macro keycloak_oidc_client}
  KeycloakOIDCClient({
    required OIDCClientConfig config,
  }) : super(config: config);

  ///
  Future<OIDCToken> authenticateProvider({
    KeycloakIdentityProvider? identityProvider,
    DisplayBehavior displayBehavior = DisplayBehavior.browser,
    List<String>? scopes,
    List<OIDCPromptValue>? prompt,
    String? appIdentifier,
  }) async {
    if (displayBehavior == DisplayBehavior.nativeIfPossible &&
        (identityProvider == KeycloakIdentityProvider.apple ||
            identityProvider == KeycloakIdentityProvider.google)) {
      try {
        final authorizationIdentityProvider =
            identityProvider == KeycloakIdentityProvider.apple
                ? NativeIdentityProvider.apple
                : NativeIdentityProvider.google;

        final authorizationResult = await super.authorize(
          identityProvider: authorizationIdentityProvider,
          displayBehavior: DisplayBehavior.nativeIfPossible,
          scope: scopes,
          prompt: prompt,
        );

        if (identityProvider == KeycloakIdentityProvider.apple) {
          assert(
            appIdentifier != null,
            '"appIdentifier" must not be `null` for apple token exchange!',
          );

          return super.exchangeToken(
            subjectToken: authorizationResult.authorizationCode,
            subjectTokenType: _kAppleSubjectTokenType,
            additionalParameters: {
              'subject_issuer': _kAppleTokenExchangeSubjectIssuer,
              'app_identifier': appIdentifier!,
              'user_profile': jsonEncode(authorizationResult.userInfo),
            },
          );
        } else {
          return super.exchangeToken(
            subjectToken: authorizationResult.authorizationCode,
            subjectTokenType: OIDCSubjectTokenType.accessToken,
            additionalParameters: {
              'subject_issuer': _kGoogleTokenExchangeSubjectIssuer,
            },
          );
        }
      } on AuthorizeException catch (e) {
        if (e.errorCode == AuthorizeErrorCode.nativeAuthorizationNotSupported) {
          // ignore if exception was thrown because native sign in is not
          // possible
        } else {
          throw AuthenticationFlowException(
            code: AuthenticationFlowErrorCode.authorizationFailed,
            message: e.message,
          );
        }
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
