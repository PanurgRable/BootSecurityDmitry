package ru.kata.spring.boot_security.demo.models;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import java.util.*;

@Entity
@NoArgsConstructor
@Getter
@Setter
@Table(name = "users")
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name="id")
    private Long id;

    @Column(name = "name")
    private String firstName;

    @Column(name = "last_name")
    private String lastName;

    @Column(name = "email")
    private String email;

    @Column(name = "username")
    private String username;

    @Column(name = "password")
    private String password;

    @ManyToMany(fetch = FetchType.LAZY, cascade = {CascadeType.ALL})
    @JoinTable(name = "users_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Collection<Role> roles = new HashSet<>();

    public User(String firstName, String lastName, String email, String username, String password) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
        this.username = username;
        this.password = password;
    }

    public User(User user) {
        this.firstName = user.getFirstName();
        this.lastName = user.getLastName();
        this.email = user.getEmail();
        this.username = user.getUsername();
        this.password = user.getPassword();
        this.roles = user.getRoles();
    }

    public String getShortRoles() {
        if (roles.isEmpty()) {
            return "NONE";
        } else if (roles.toString().equals("[ROLE_USER]")) {
            return "USER";
        } else if (roles.toString().equals("[ROLE_ADMIN]")) {
            return "ADMIN";
        }
        return "ADMIN USER";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return getFirstName().equals(user.getFirstName()) && getLastName().equals(user.getLastName()) && getEmail().equals(user.getEmail()) && getUsername().equals(user.getUsername());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getFirstName(), getLastName(), getEmail(), getUsername());
    }

    @Override
    public String toString() {
        return "UserEntity{" +
                "id=" + id +
                ", firstName='" + firstName + '\'' +
                ", lastName='" + lastName + '\'' +
                ", email='" + email + '\'' +
                ", username='" + username + '\'' +
                '}';
    }

    public static List<User> getUsersListDefault() {
        List<User> userList = new ArrayList<>();
        userList.add(new User("name1", "syrname1", "name1@gmail.com", "name1", "$2a$10$En87uG48XcYSmqqo/qUyMuYCzgmno0l2iLbnCHYLYuMrL3CBYOAPq")); //100
        userList.add(new User("name2", "syrname2", "name2@gmail.com", "name2", "$2a$10$En87uG48XcYSmqqo/qUyMuYCzgmno0l2iLbnCHYLYuMrL3CBYOAPq")); //100
        userList.add(new User("name3", "syrname3", "name3@hotmail.com", "name3", "$2a$10$En87uG48XcYSmqqo/qUyMuYCzgmno0l2iLbnCHYLYuMrL3CBYOAPq")); //100
        userList.add(new User("name4", "syrname4", "name4@gmail.com", "name4", "$2a$10$En87uG48XcYSmqqo/qUyMuYCzgmno0l2iLbnCHYLYuMrL3CBYOAPq")); //100
        userList.add(new User("name5", "syrname5", "name5@mail.eu", "name5", "$2a$10$En87uG48XcYSmqqo/qUyMuYCzgmno0l2iLbnCHYLYuMrL3CBYOAPq")); //100
        return userList;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles != null
                ? new HashSet<>(roles)
                : Collections.emptySet();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}