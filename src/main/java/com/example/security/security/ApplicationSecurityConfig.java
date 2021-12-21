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
        // указаваем какие запросы обрабатывать через пароль
        // а какие не требуют логирования пользователя
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/", "index.html", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();

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

    //step 5
    @Override
    @Bean
    public UserDetailsService userDetailsServiceBean() throws Exception {

        UserDetails annaSmithUser = User.builder()
                .username("anna")
                .password(passwordEncoder.encode("12345") ) // PasswordConfig занимаеться шифрование пароля.
                .roles(ApplicationUserRole.STUDENT.name()  ) // назначаем роль
                .build();



        //step 7
        UserDetails lindaUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("12345"))
                .roles(ApplicationUserRole.ADMIN.name())
                .build();

        //step 8
        UserDetails tomUser = User.builder()
                .username("tomUser")
                .password(passwordEncoder.encode("12345"))
                .roles(ApplicationUserRole.ADMINTRAINEE.name())
                .build();

        return new InMemoryUserDetailsManager(
                annaSmithUser,
                lindaUser,
                tomUser
        );
    }
}
