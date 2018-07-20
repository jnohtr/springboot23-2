package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter{

    @Bean
    public PasswordEncoder encoder() {

        return new BCryptPasswordEncoder();

    }

    @Autowired
    private SSUserDetailsService userDetailsService;

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetailsService userDetailsServiceBean() throws Exception {

        return new SSUserDetailsService(userRepository);

    }

    @Override
    protected void configure (HttpSecurity http) throws Exception {

        http
                .authorizeRequests()

                .antMatchers("/", "/h2-console/**", "/register").permitAll()

//                .antMatchers("/").access("hasAnyAuthority('USER','ADMIN')")
//                .antMatchers("/admin").access("hasAuthority('ADMIN')")

                .anyRequest().authenticated()

                .and()
                .formLogin().loginPage("/login").permitAll()

                .and()
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/login").permitAll().permitAll()

                .and()
                .httpBasic();

        http
                .csrf().disable();
        http
                .headers().frameOptions().disable();

    }

    @Override
    protected void configure (AuthenticationManagerBuilder auth) throws Exception {

//        PasswordEncoder p = new BCryptPasswordEncoder();

        auth
//                .inMemoryAuthentication()
//
//                .withUser("jim").password(p.encode("pass")).authorities("ADMIN")
//                .and()
//                .withUser("user").password(p.encode("pass")).authorities("USER")
//                .and()
////                .withUser("jim").password(p.encode("pass")).roles("ADMIN")
////                .and()
////                .withUser("user").password("password").roles("USER")
////                .and()
//                .passwordEncoder(new BCryptPasswordEncoder());

//                .userDetailsService(userDetailsServiceBean())

                .userDetailsService(userDetailsServiceBean()).passwordEncoder(encoder());

    }

//    @Bean
//    @SuppressWarnings("deprecation")
//    public static NoOpPasswordEncoder passwordEncoder() {
//
//        return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
//
//    }
}
