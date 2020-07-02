package com.okta.spring.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

import com.fasterxml.jackson.databind.introspect.WithMember;

import java.net.URI;
import java.util.Collections;

@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class CodeFlowExampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(CodeFlowExampleApplication.class, args);
    }

    /**
     * The default Spring logout behavior redirects a user back to {code}/login?logout{code}, so you will likely want
     * to change that.  The easiest way to do this is by extending from {@link WebSecurityConfigurerAdapter}.
     */
    @Configuration
    public class SecurityConfig extends WebSecurityConfigurerAdapter {

        @Autowired
        ClientRegistrationRepository clientRegistrationRepository; 

		OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler() { 
            OidcClientInitiatedLogoutSuccessHandler successHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
            successHandler.setPostLogoutRedirectUri("http://localhost:8080/");
            return successHandler;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests()

                    // allow anonymous access to the root page
                    .antMatchers("/").permitAll()

                    // all other requests
                    .anyRequest().authenticated()

                    // RP-initiated logout
                    .and().logout().logoutSuccessHandler(oidcLogoutSuccessHandler()) 

                    // enable OAuth2/OIDC
                    .and().oauth2Login();
        }
    }
	
    /**
     * This example controller has endpoints for displaying the user profile info on {code}/{code} and "you have been
     * logged out page" on {code}/post-logout{code}.
     */
    @Controller
    public class ExampleController {

        @GetMapping("/")
        public String home() {
        	System.out.println("Home");
            return "home";
        }

        @GetMapping("/profile")
        @PreAuthorize("hasAuthority('SCOPE_profile')")
        public ModelAndView userDetails(OAuth2AuthenticationToken authentication) {
            return new ModelAndView("userProfile" , Collections.singletonMap("details", authentication.getPrincipal().getAttributes()));
        }
    }
}
