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

/// {@template native_authorization_exception}
///
/// {@endtemplate}
class NativeAuthorizationException implements Exception {
  /// {@macro native_authorization_exception}
  const NativeAuthorizationException({
    this.message,
  });

  final String? message;
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

    if (accessToken == null) {}

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
