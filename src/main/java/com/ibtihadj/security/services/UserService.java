package com.ibtihadj.security.services;

import com.ibtihadj.security.exceptions.*;
import com.ibtihadj.security.requests.ChangePasswordRequest;
import com.ibtihadj.security.requests.LoginRequest;
import com.ibtihadj.security.requests.RegisterRequest;
import com.ibtihadj.security.responses.HttpSuccessResponse;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import javax.mail.MessagingException;
import java.io.UnsupportedEncodingException;

public interface UserService extends UserDetailsService {

    void addRoleToUser(String roleName, String username) throws RoleNotFoundException, RoleAlreadyExistException;

    String authenticate(LoginRequest request) throws UserNotFoundException;

    HttpSuccessResponse storeUser(RegisterRequest request) throws RoleNotFoundException, UserAlreadyExistException, RoleAlreadyExistException, ParametreNotValidate;

    HttpSuccessResponse authUser(Authentication authentication);

    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;

    UserDetails loadByEmail(String email);

    HttpSuccessResponse onGet_password_Token(HttpServletRequest servletRequest, String email) throws MessagingException, UnsupportedEncodingException, UserNotFoundException, jakarta.mail.MessagingException;

    HttpSuccessResponse changePasswordRequest(ChangePasswordRequest request) throws ParametreNotValidate, UserNotFoundException;

    HttpSuccessResponse allUser();


}
