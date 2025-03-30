package com.yoanesber.form_auth_demo.service;

public interface PasswordEncoderService {
    // to encode a string
    String encode(String rawPassword);

    // to validate the encoded string
    boolean matches(String rawPassword, String encodedPassword);
}
