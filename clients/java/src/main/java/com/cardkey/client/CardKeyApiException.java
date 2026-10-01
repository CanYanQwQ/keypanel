package com.cardkey.client;

public class CardKeyApiException extends RuntimeException {
    public CardKeyApiException(String message) { super(message); }
    public CardKeyApiException(String message, Throwable cause) { super(message, cause); }
}
