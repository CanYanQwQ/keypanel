package com.cardkey.client

fun main() {
    val config = ClientConfig()
    println("CardKey Kotlin client example")
    println("Configured base URL: ${config.baseUrl}")
    println("Set CARDKEY_APP_ID and CARDKEY_APP_SECRET before making requests.")
    println("Example: CardKeyClient(config).query(CardKeyValue.Plain(\"ABCD-EFGH-JKMN-PQRS\"))")
}
