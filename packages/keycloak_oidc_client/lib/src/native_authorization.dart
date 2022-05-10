import 'package:flutter/services.dart';
import 'package:google_sign_in/google_sign_in.dart';
import 'package:sign_in_with_apple/sign_in_with_apple.dart';

const List<AppleIDAuthorizationScopes> kDefaultAppleScopes = [
  AppleIDAuthorizationScopes.email,
  AppleIDAuthorizationScopes.fullName,
];

const List<String> kDefaultGoogleScopes = [
  'email',
  'https://www.googleapis.com/auth/userinfo.profile',
];

enum NativeAuthorizationErrorCode {
  canceled,
  failed,
}

/// {@template native_authorization_exception}
///
/// {@endtemplate}
class NativeAuthorizationException implements Exception {
  /// {@macro native_authorization_exception}
  const NativeAuthorizationException({
    this.message,
    this.code = NativeAuthorizationErrorCode.failed,
  });

  factory NativeAuthorizationException.fromSignInWithAppleException(
    SignInWithAppleException exception,
  ) {
    if (exception is SignInWithAppleAuthorizationException) {
      if (exception.code == AuthorizationErrorCode.canceled) {
        return NativeAuthorizationException(
          code: NativeAuthorizationErrorCode.canceled,
          message: exception.message,
        );
      } else {
        return NativeAuthorizationException(
          message: exception.message,
        );
      }
    } else if (exception is SignInWithAppleCredentialsException) {
      return NativeAuthorizationException(
        message: exception.message,
      );
    } else if (exception is PlatformException) {
      return NativeAuthorizationException(
        message: (exception as PlatformException).message,
      );
    } else {
      return const NativeAuthorizationException();
    }
  }

  final String? message;

  final NativeAuthorizationErrorCode code;
}

/// {@template authorization_result}
///
/// {@endtemplate}
class AppleAuthorizationResult {
  /// {@macro authorization_result}
  const AppleAuthorizationResult({
    required this.authorizationCode,
    this.userInfo,
  });

  final String authorizationCode;
  final Map<String, dynamic>? userInfo;
}

/// {@template native_authorization}
///
/// {@endtemplate}
class NativeAuthorization {
  ///
  Future<AppleAuthorizationResult> apple({
    List<AppleIDAuthorizationScopes> scopes = kDefaultAppleScopes,
  }) async {
    try {
      final appleResponse = await SignInWithApple.getAppleIDCredential(
        scopes: scopes,
      );

      return AppleAuthorizationResult(
        authorizationCode: appleResponse.authorizationCode,
        userInfo: appleResponse.user,
      );
    } catch (e) {
      throw NativeAuthorizationException(message: e.toString());
    }
  }

  ///
  Future<String?> google({
    List<String> scopes = kDefaultGoogleScopes,
  }) async {
    final googleSignIn = GoogleSignIn(
      scopes: scopes,
    );

    String? accessToken;

    try {
      if (await googleSignIn.isSignedIn()) {
        await googleSignIn.disconnect();
      }

      final googleAccount = await googleSignIn.signIn();
      final authentication = await googleAccount!.authentication;

      accessToken = authentication.accessToken;
    } catch (e) {
      if (e is PlatformException) {
        throw NativeAuthorizationException(message: e.message);
      } else {
        throw NativeAuthorizationException(message: e.toString());
      }
    }

    return accessToken;
  }
}

extension AuthorizationCredentialAppleIDX on AuthorizationCredentialAppleID {
  Map<String, dynamic>? get user {
    return <String, dynamic>{
      'name': {
        'firstName': givenName,
        'lastName': familyName,
      }
    };
  }
}
