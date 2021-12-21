package com.example.security.auth;

import com.example.security.security.ApplicationUserRole;
import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao{

    private final PasswordEncoder   passwordEncoder;

    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers(){
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
            new ApplicationUser(
                "anna",
                    passwordEncoder.encode("12345"),
                    ApplicationUserRole.STUDENT.getGrantedAuthority(),
                    true,
                    true,
                    true,
                    true
            ),
                new ApplicationUser(
                        "linda",
                        passwordEncoder.encode("12345"),
                        ApplicationUserRole.ADMIN.getGrantedAuthority(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        "tom",
                        passwordEncoder.encode("12345"),
                        ApplicationUserRole.ADMINTRAINEE.getGrantedAuthority(),
                        true,
                        true,
                        true,
                        true
                )
        );

        return applicationUsers;
    }
}
