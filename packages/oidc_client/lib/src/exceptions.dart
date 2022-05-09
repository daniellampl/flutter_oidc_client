import 'package:flutter/services.dart';
import 'package:sign_in_with_apple/sign_in_with_apple.dart';

/// Describes why an authentication flow failed.
enum AuthenticationFlowErrorCode {
  /// The user authorization failed.
  authorizationFailed,

  /// The user has already been authenticated via another identity provider.
  userAlreadyExists,

  /// The user cancelled the authentication flow.
  cancelled,

  /// No token was returned from the authentication server.
  noTokenReceived,

  /// An unexpected error occurred during the authentication flow.
  failed,
}

/// Thrown when an authentication flow fails.
class AuthenticationFlowException implements Exception {
  const AuthenticationFlowException({
    this.code = AuthenticationFlowErrorCode.failed,
    this.message,
  });

  factory AuthenticationFlowException.fromPlatformException(
    PlatformException exception,
  ) {
    final message = exception.message;

    if (message == null) {
      throw const AuthenticationFlowException();
    }

    if (message.contains('User cancelled flow') ||
        message.contains('The operation couldn’t be completed.')) {
      return AuthenticationFlowException(
        code: AuthenticationFlowErrorCode.cancelled,
        message: exception.message,
      );
    } else if (message.contains('User already exists')) {
      return AuthenticationFlowException(
        code: AuthenticationFlowErrorCode.userAlreadyExists,
        message: exception.message,
      );
    }

    throw AuthenticationFlowException(
      message: exception.message,
    );
  }

  factory AuthenticationFlowException.fromSignInWithAppleException(
    SignInWithAppleException exception,
  ) {
    if (exception is SignInWithAppleAuthorizationException) {
      if (exception.code == AuthorizationErrorCode.canceled) {
        return AuthenticationFlowException(
          code: AuthenticationFlowErrorCode.cancelled,
          message: exception.message,
        );
      } else {
        return AuthenticationFlowException(
          code: AuthenticationFlowErrorCode.cancelled,
          message: exception.message,
        );
      }
    } else if (exception is SignInWithAppleCredentialsException) {
      return AuthenticationFlowException(
        message: exception.message,
      );
    } else if (exception is PlatformException) {
      return AuthenticationFlowException(
        message: (exception as PlatformException).message,
      );
    } else {
      return const AuthenticationFlowException();
    }
  }

  final String? message;

  final AuthenticationFlowErrorCode code;
}

/// Describes why an OIDCauthorization attempt failed.
enum AuthorizeErrorCode {
  /// No authorization code was returned from the "authorie" endpoint.
  noAuthorizationCodeReceived,

  /// Native authorization is not supported on the given platform.
  nativeAuthorizationNotSupported,

  /// An unexpected error occurred during authorization.
  failed,
}

/// Thrown when the user authorization fails.
class AuthorizeException implements Exception {
  const AuthorizeException({
    this.errorCode = AuthorizeErrorCode.failed,
    this.message,
  });

  final AuthorizeErrorCode errorCode;

  final String? message;
}

/// Thrown when the token exchange authentication fails.
class TokenExchangeFailedException implements Exception {}

/// Thrown when the refreshing process for an access token failed.
class TokenRefreshFailedException implements Exception {}

/// Thrown when the logout request failed.
class LogoutFailedException implements Exception {}
