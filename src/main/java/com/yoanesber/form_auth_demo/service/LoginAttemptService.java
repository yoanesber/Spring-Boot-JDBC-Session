package com.yoanesber.form_auth_demo.service;

public interface LoginAttemptService {
    // to check if the login attempts exceed the maximum allowed attempts; if yes, then the user is locked
    void loginFailed(String userName) throws Exception;

    // if the login is successful, then the login attempts are reset
    void loginSucceeded(String userName);
}
