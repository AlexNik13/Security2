package com.example.security.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "index.html", "/css/*", "/js/*")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin();

        /*.authorizeRequests()

                .antMatchers("/", "index.html", "/css/*", "/js/*") - какие запросы не подподают под логирование
                .permitAll()        -   все перечисленые запросы
                - белый список для запросов
                .anyRequest()
                .authenticated()
                .and()
                .formLogin();
        */

        /*.authorizeRequests()  - авторизируемые запросы
          .anyRequest()         - ве запросы
          .authenticated()      - аутентифицирована
          .and()                -
          .formLogin();       - как логиниться

         */


    }

    //step5
    @Override
    @Bean
    public UserDetailsService userDetailsServiceBean() throws Exception {

        UserDetails annaSmithUser = User.builder()
                .username("anna")
                .password(passwordEncoder.encode("12345") )
                .roles("STUDENTS")
                .build();

        return new InMemoryUserDetailsManager(annaSmithUser);
    }
}
