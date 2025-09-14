package ru.kata.spring.boot_security.demo.providers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import ru.kata.spring.boot_security.demo.services.UserServiceImpl;

import java.util.Collection;

@Component
public class AuthProvider implements AuthenticationProvider {
    private UserServiceImpl userService;

    private PasswordEncoder passwordEncoder;

    @Autowired
    public AuthProvider(UserServiceImpl userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    public Authentication authenticate(Authentication authentication) throws AuthenticationException
    {
        String email = authentication.getName();
        String password = (String) authentication.getCredentials();

        UserDetails user = userService.loadUserByEmail(email);
        if (user != null)
        {
            if(!passwordEncoder.matches(password, user.getPassword()))
            {
                throw new BadCredentialsException("Неверный пароль");
            }

            Collection<? extends GrantedAuthority> authorities = user.getAuthorities();

            return new UsernamePasswordAuthenticationToken(user, password, authorities);
        }
        else {
            throw new BadCredentialsException("Пользователь не найден");
        }
    }

    public boolean supports(Class<?> arg)
    {
        return true;
    }
}
