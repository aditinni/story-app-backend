package minijira.example.tracker.service;

import minijira.example.tracker.dto.AuthRequest;
import minijira.example.tracker.model.User;
import minijira.example.tracker.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    public String registerUser(AuthRequest request)
    {
        if(userRepository.existsByEmail(request.getEmail())){
            return "Email already exists";
        }
        User user  = new User();
        user.setEmail(request.getEmail());
        user.setName(request.getName());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        userRepository.save(user);

        return "User registered successfully";

    }

    public boolean authenticateUser(AuthRequest request) {
        Optional<User> userOptional = userRepository.findByEmail(request.getEmail());

        if (userOptional.isPresent()) {
            User user = userOptional.get();
            // Compare raw password from user with hashed password in DB
            return passwordEncoder.matches(request.getPassword(), user.getPassword());
        }
        return false;
    }
}
