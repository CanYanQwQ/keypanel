use cardkey_api_client_example::{encrypt_card_key, CardKeyClient};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url = std::env::var("CARDKEY_BASE_URL")?;
    let app_id = std::env::var("CARDKEY_APP_ID")?;
    let secret = std::env::var("CARDKEY_APP_SECRET")?;
    let action = std::env::args().nth(1).unwrap_or_else(|| "verify".into());
    let plaintext = std::env::args().nth(2).unwrap_or_else(|| "ABCD-EFGH-JKMN-PQRS".into());
    let card = encrypt_card_key(&plaintext, &secret, &app_id)?;
    let input = json!({ "card_key": card, "device_id": "device-001", "count": 1, "force": false });
    let client = CardKeyClient::new(&base_url, &app_id, &secret)?;
    let result = match action.as_str() {
        "verify" => client.verify(input)?,
        "activate" => client.activate(input)?,
        "consume" => client.consume(input)?,
        "query" => client.query(input)?,
        "unbind" => client.unbind(input)?,
        _ => return Err("action must be verify, activate, consume, query, or unbind".into()),
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
