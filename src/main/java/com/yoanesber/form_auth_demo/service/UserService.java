package com.yoanesber.form_auth_demo.service;

import com.yoanesber.form_auth_demo.entity.User;

public interface UserService {
    // to find a user by its username
    User findByUserName(String userName);

    // to find a user by its id
    User findByUserId(Long userId);

    // to update the last login of a user
    User updateLastLogin(String userName) throws Exception;

    // to lock the account of a user
    void lockAccount(String userName) throws Exception;

    // to set the account of a user to expire
    void setAccountToExpire(String userName) throws Exception;

    // to set the credentials of a user to expire
    void setCredentialsToExpire(String userName) throws Exception;
}
