import 'package:flutter/services.dart';

/// Describes why an authentication flow failed.
enum AuthenticationFlowErrorCode {
  /// The user authorization failed.
  authorizationFailed,

  /// The user has already been authenticated via another identity provider.
  userAlreadyExists,

  /// The user cancelled the authentication flow.
  canceled,

  /// No token was returned from the authentication server.
  noTokenReceived,

  /// No authorization code was returned by the identity provider.
  noAuthorizationCodeReceived,

  /// An unexpected error occurred during the authentication flow.
  failed,
}

/// Thrown when an authentication flow fails.
class AuthenticateException implements Exception {
  const AuthenticateException({
    this.code = AuthenticationFlowErrorCode.failed,
    this.message,
  });

  factory AuthenticateException.fromPlatformException(
    PlatformException exception,
  ) {
    final message = exception.message;

    if (message == null) {
      throw const AuthenticateException();
    }

    if (message.contains('User cancelled flow') ||
        message.contains('The operation couldn’t be completed.')) {
      return AuthenticateException(
        code: AuthenticationFlowErrorCode.canceled,
        message: exception.message,
      );
    } else if (message.contains('User already exists')) {
      return AuthenticateException(
        code: AuthenticationFlowErrorCode.userAlreadyExists,
        message: exception.message,
      );
    }

    throw AuthenticateException(
      message: exception.message,
    );
  }

  final String? message;

  final AuthenticationFlowErrorCode code;
}

/// Thrown when the token exchange authentication fails.
class TokenExchangeException implements Exception {}

/// Thrown when the refreshing process for an access token failed.
class TokenRefreshException implements Exception {}
