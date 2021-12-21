package com.example.security.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
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
       //         .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
       //         .and()


                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/", "index.html", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())

                /*
                заменили на анатацыю в "StudentManagementController"
        @PreAuthorize("hasAuthority('student:write')")
                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_READ.getPermission())
                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_READ.getPermission())
                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_READ.getPermission())

        @PreAuthorize("hasAnyRole('ADMIN', 'ADMINTRAINEE')")
                .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(), ApplicationUserRole.ADMINTRAINEE.name())
               */
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .loginPage("/login").permitAll()
                .defaultSuccessUrl("/courses", true)
                .and()
                .rememberMe()
                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
                    .key("somethingverysecured")
                .and()
                .logout()
                .logoutUrl("/logout")
                .logoutRequestMatcher(new AntPathRequestMatcher("logoutUrl", "GET"))
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID", "Idea-a720b26b")
                .logoutSuccessUrl("/login")

                ;

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
               // .roles(ApplicationUserRole.STUDENT.name()  ) // назначаем роль
                .authorities(ApplicationUserRole.STUDENT.getGrantedAuthority())
                .build();



        //step 7
        UserDetails lindaUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("12345"))
              //  .roles(ApplicationUserRole.ADMIN.name())
                .authorities(ApplicationUserRole.ADMIN.getGrantedAuthority())
                .build();

        //step 8
        UserDetails tomUser = User.builder()
                .username("tomUser")
                .password(passwordEncoder.encode("12345"))
              //  .roles(ApplicationUserRole.ADMINTRAINEE.name())
                .authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthority())
                .build();

        return new InMemoryUserDetailsManager(
                annaSmithUser,
                lindaUser,
                tomUser
        );
    }
}
