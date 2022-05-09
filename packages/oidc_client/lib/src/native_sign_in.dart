import 'package:flutter/services.dart';
import 'package:google_sign_in/google_sign_in.dart';
import 'package:oidc_client/src/exceptions.dart';
import 'package:oidc_client/src/oidc_client.dart';
import 'package:sign_in_with_apple/sign_in_with_apple.dart';

const List<AppleIDAuthorizationScopes> kDefaultAppleScopes = [
  AppleIDAuthorizationScopes.email,
  AppleIDAuthorizationScopes.fullName,
];

const List<String> kDefaultGoogleScopes = [
  'email',
  'https://www.googleapis.com/auth/userinfo.profile',
];

class NativeSignIn {
  Future<AuthorizationResult> apple({
    List<AppleIDAuthorizationScopes> scopes = kDefaultAppleScopes,
  }) async {
    try {
      final appleResponse = await SignInWithApple.getAppleIDCredential(
        scopes: scopes,
      );

      return AuthorizationResult(
        authorizationCode: appleResponse.authorizationCode,
        userInfo: appleResponse.user,
      );
    } catch (e) {
      throw AuthorizeException(message: e.toString());
    }
  }

  Future<AuthorizationResult> google({
    List<String> scopes = kDefaultGoogleScopes,
  }) async {
    final googleSignIn = GoogleSignIn(
      scopes: scopes,
    );

    String? accessToken;

    try {
      final googleAccount = await googleSignIn.signIn();
      final authentication = await googleAccount!.authentication;

      if (await googleSignIn.isSignedIn()) {
        await googleSignIn.disconnect();
      }

      accessToken = authentication.accessToken;
    } catch (e) {
      if (e is PlatformException) {
        throw AuthorizeException(message: e.message);
      } else {
        throw AuthorizeException(message: e.toString());
      }
    }

    if (accessToken == null) {
      throw const AuthorizeException(
        message: 'No access token received from Google sign in!',
        errorCode: AuthorizeErrorCode.noAuthorizationCodeReceived,
      );
    }

    return AuthorizationResult(
      authorizationCode: accessToken,
    );
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
