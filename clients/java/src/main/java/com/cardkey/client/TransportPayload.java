package com.cardkey.client;

public record TransportPayload(String iv, String data, String tag) {}
