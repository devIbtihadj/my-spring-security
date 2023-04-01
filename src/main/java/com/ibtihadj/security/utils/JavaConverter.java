package com.ibtihadj.security.utils;

import com.ibtihadj.security.entities.User;
import com.ibtihadj.security.requests.RegisterRequest;
import com.ibtihadj.security.responses.UserResponse;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Component;

@Component
public class JavaConverter {

    public User registerToUser(RegisterRequest request) {
        User user = new User();
        BeanUtils.copyProperties(request, user);
        return user;
    }

    public UserResponse userToUserResponse(User user) {
        UserResponse response = new UserResponse();
        BeanUtils.copyProperties(user, response);
        return response;
    }
}
