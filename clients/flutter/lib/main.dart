import 'client.dart';
import 'models.dart';

export 'client.dart';
export 'models.dart';
export 'signer.dart';
export 'transport_crypto.dart';

void main() {
  final config = ClientConfig(
    baseUrl: Uri.parse('https://example.invalid'),
    appId: 'ak_test_replace_me',
    appSecret: 'sk_test_replace_me',
  );
  // No network call and no secret/card-key output in this example.
  final client = CardKeyClient(config);
  assert(client.config.baseUrl.host == 'example.invalid');
}
