package minijira.example.tracker.controller;

import minijira.example.tracker.configuration.JwtUtil;
import minijira.example.tracker.dto.AuthRequest;
import minijira.example.tracker.dto.AuthResponse;
import minijira.example.tracker.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "https://my-react-app-nine-swart.vercel.app/")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> signup(@RequestBody AuthRequest request) {
        String result = authService.registerUser(request);
        if (result.equals("Email already exists!")) {
            return ResponseEntity.badRequest().body(new AuthResponse(null, result));
        }
        return ResponseEntity.ok(new AuthResponse(null, result));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest request) {
        boolean isAuthenticated = authService.authenticateUser(request);

        if (isAuthenticated) {
            // GENERATE THE REAL TOKEN!
            String token = jwtUtil.generateToken(request.getEmail());
            return ResponseEntity.ok(new AuthResponse(token, "Login successful"));
        } else {
            return ResponseEntity.status(401).body(new AuthResponse(null, "Invalid email or password"));
        }
    }

}
