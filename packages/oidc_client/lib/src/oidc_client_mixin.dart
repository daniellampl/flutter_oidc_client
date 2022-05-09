import 'dart:convert';

import 'package:http/http.dart' as http;

mixin OIDCClientMixin {
  ///
  Future<String> fetchEndSessionUrlFromDiscoveryUrl(
    String discoveryUrl,
  ) async {
    final discoveryContent = await fetchDiscoveryUrlContent(discoveryUrl);
    return discoveryContent['end_session_endpoint'] as String;
  }

  ///
  Future<Map<String, dynamic>> fetchDiscoveryUrlContent(
    String discoveryUrl,
  ) async {
    final response = await http.get(Uri.parse(discoveryUrl));
    return jsonDecode(response.body) as Map<String, dynamic>;
  }
}
