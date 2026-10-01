package com.cardkey.client;

public final class Main {
    private Main() {}
    public static void main(String[] args) {
        ClientConfig config = ClientConfig.fromEnvironment();
        System.out.println("CardKey Java client example");
        System.out.println("Configured base URL: " + config.baseUrl());
        System.out.println("Set CARDKEY_APP_ID and CARDKEY_APP_SECRET before making requests.");
        System.out.println("The example does not call the server or print secrets/card keys.");
    }
}
