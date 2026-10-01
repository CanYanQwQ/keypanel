package com.cardkey.client;

import java.util.Objects;

public sealed interface CardKeyValue permits PlainCardKey, EncryptedCardKey {
    static CardKeyValue plain(String value) { return new PlainCardKey(value); }
    static CardKeyValue encrypted(TransportPayload payload) { return new EncryptedCardKey(payload); }
}

record PlainCardKey(String value) implements CardKeyValue {
    PlainCardKey { Objects.requireNonNull(value, "value"); }
}

record EncryptedCardKey(TransportPayload payload) implements CardKeyValue {
    EncryptedCardKey { Objects.requireNonNull(payload, "payload"); }
}
