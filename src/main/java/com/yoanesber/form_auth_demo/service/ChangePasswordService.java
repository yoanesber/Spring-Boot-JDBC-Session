package com.yoanesber.form_auth_demo.service;

import com.yoanesber.form_auth_demo.entity.User;

public interface ChangePasswordService {
    // to force a user to change its password
    User forceChange(String newPassword, String confirmPassword, Long userId) throws Exception;
}
