package minijira.example.tracker.service;

import minijira.example.tracker.model.User;
import minijira.example.tracker.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    // This is the one method Spring Security forces us to write.
    // It says: "Hey, someone is trying to log in with this email. Do they exist?"
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        // 1. Look for the user in our MongoDB database
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));

        // 2. If found, convert our MongoDB 'User' into a Spring Security 'UserDetails' object
        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                user.getPassword(),
                new ArrayList<>() // This empty array is for user roles (like ADMIN or USER), which we aren't using right now
        );
    }
}
