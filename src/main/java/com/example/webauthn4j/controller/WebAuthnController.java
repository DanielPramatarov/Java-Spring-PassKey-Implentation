package com.example.webauthn4j.controller;

import com.example.webauthn4j.entity.Authenticator;
import com.example.webauthn4j.entity.User;
import com.example.webauthn4j.repository.AuthenticatorRepository;
import com.example.webauthn4j.repository.UserRepository;
import com.webauthn4j.util.Base64UrlUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.SecureRandom;
import java.util.*;

@RestController
@RequestMapping("/api/webauthn")
@CrossOrigin(origins = "*")
public class WebAuthnController {
    
    
    private static final Logger logger = LoggerFactory.getLogger(WebAuthnController.class);
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private AuthenticatorRepository authenticatorRepository;
    
    private final SecureRandom random = new SecureRandom();
    private final Map<String, String> challengeStore = new HashMap<>();
    private final Map<String, byte[]> userHandleStore = new HashMap<>();
    
    @PostMapping("/register/begin")
    public ResponseEntity<?> beginRegistration(@RequestBody Map<String, String> request) {
        logger.info("=== BEGIN REGISTRATION ===");
        logger.info("Request received: {}", request);
        
        String username = request.get("username");
        logger.info("Username: {}", username);
        
        
        Optional<User> existingUser = userRepository.findByUsername(username);
        logger.info("Existing user check: {}", existingUser.isPresent());
        
        if (existingUser.isPresent()) {
            logger.warn("User already exists: {}", username);
            return ResponseEntity.badRequest().body(Map.of("error", "User already exists"));
        }
        
        
        byte[] userHandle = new byte[32];
        random.nextBytes(userHandle);
        userHandleStore.put(username, userHandle);
        logger.info("Generated user handle length: {}", userHandle.length);
        
        byte[] challengeBytes = new byte[32];
        random.nextBytes(challengeBytes);
        String challengeB64 = Base64UrlUtil.encodeToString(challengeBytes);
        logger.info("Generated challenge: {}", challengeB64);
        
        
        challengeStore.put(username, challengeB64);
        logger.info("Stored challenge for user: {}", username);
        
        
        Map<String, Object> response = new HashMap<>();
        response.put("challenge", challengeB64);
        response.put("rp", Map.of("name", "Passkey Demo", "id", "localhost"));
        response.put("user", Map.of(
            "id", Base64UrlUtil.encodeToString(userHandle),
            "name", username,
            "displayName", username
        ));
        response.put("pubKeyCredParams", List.of(
            Map.of("type", "public-key", "alg", -7), 
            Map.of("type", "public-key", "alg", -257) 
        ));
        response.put("authenticatorSelection", Map.of(
            "authenticatorAttachment", "platform",
            "userVerification", "required",
            "residentKey", "required"
        ));
        response.put("timeout", 60000);
        response.put("attestation", "none");
        response.put("excludeCredentials", new ArrayList<>()); 
        
        logger.info("Response to send: {}", response);
        logger.info("=== END BEGIN REGISTRATION ===");
        
        return ResponseEntity.ok(response);
    }
    
    @PostMapping("/register/finish")
    public ResponseEntity<?> finishRegistration(@RequestBody Map<String, Object> request) {
        try {
            logger.info("=== FINISH REGISTRATION ===");
            logger.info("Request received: {}", request);
            
            String username = (String) request.get("username");
            logger.info("Username: {}", username);
            
            String storedChallenge = challengeStore.get(username);
            byte[] userHandle = userHandleStore.get(username);
            
            logger.info("Stored challenge found: {}", storedChallenge != null);
            logger.info("User handle found: {}", userHandle != null);
            
            if (storedChallenge == null || userHandle == null) {
                logger.error("Challenge or user handle not found for user: {}", username);
                return ResponseEntity.badRequest().body(Map.of("error", "Challenge or user handle not found"));
            }
            
            
            Map<String, Object> credential = (Map<String, Object>) request.get("credential");
            logger.info("Credential data: {}", credential);
            
            String credentialId = (String) credential.get("id");
            Map<String, Object> response = (Map<String, Object>) credential.get("response");
            String clientDataJSON = (String) response.get("clientDataJSON");
            String attestationObject = (String) response.get("attestationObject");
            
            logger.info("Credential ID: {}", credentialId);
            logger.info("Client data JSON length: {}", clientDataJSON != null ? clientDataJSON.length() : "null");
            logger.info("Attestation object length: {}", attestationObject != null ? attestationObject.length() : "null");
            
            
            try {
                Base64UrlUtil.decode(clientDataJSON);
                Base64UrlUtil.decode(attestationObject);
                Base64UrlUtil.decode(credentialId);
                logger.info("Base64 validation successful");
            } catch (Exception e) {
                logger.error("Base64 validation failed: {}", e.getMessage());
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid credential data"));
            }
            
            
            User user = new User(username, userHandle);
            logger.info("Created user object: {}", user);
            
            User savedUser = userRepository.save(user);
            logger.info("Saved user with ID: {}", savedUser.getId());
            
            
            Authenticator authenticator = new Authenticator(
                Base64UrlUtil.decode(credentialId),
                Base64UrlUtil.decode(credentialId), 
                0L, 
                savedUser
            );
            logger.info("Created authenticator object: {}", authenticator);
            
            Authenticator savedAuthenticator = authenticatorRepository.save(authenticator);
            logger.info("Saved authenticator with ID: {}", savedAuthenticator.getId());
            
            challengeStore.remove(username);
            userHandleStore.remove(username);
            logger.info("Cleaned up temporary data for user: {}", username);
            
            logger.info("=== REGISTRATION SUCCESSFUL ===");
            return ResponseEntity.ok(Map.of("status", "ok", "message", "Registration successful"));
            
        } catch (Exception e) {
            logger.error("Registration failed with exception: ", e);
            return ResponseEntity.badRequest().body(Map.of("error", "Registration failed: " + e.getMessage()));
        }
    }
    
    @PostMapping("/authenticate/begin")
    public ResponseEntity<?> beginAuthentication(@RequestBody Map<String, String> request) {
        logger.info("=== BEGIN AUTHENTICATION ===");
        logger.info("Request received: {}", request);
        
        String username = request.get("username");
        logger.info("Username: {}", username);
        
        Optional<User> userOpt = userRepository.findByUsername(username);
        logger.info("User found: {}", userOpt.isPresent());
        
        if (userOpt.isEmpty()) {
            logger.warn("User not found: {}", username);
            return ResponseEntity.badRequest().body(Map.of("error", "User not found"));
        }
        
        User user = userOpt.get();
        logger.info("Found user: ID={}, Username={}, Authenticators count={}", 
                   user.getId(), user.getUsername(), user.getAuthenticators().size());
        
        
        byte[] challengeBytes = new byte[32];
        random.nextBytes(challengeBytes);
        String challengeB64 = Base64UrlUtil.encodeToString(challengeBytes);
        challengeStore.put(username, challengeB64);
        logger.info("Generated and stored challenge: {}", challengeB64);
        
        
        List<Map<String, Object>> allowCredentials = new ArrayList<>();
        for (Authenticator auth : user.getAuthenticators()) {
            logger.info("Processing authenticator: ID={}, CredentialId length={}", 
                       auth.getId(), auth.getCredentialId().length);
            
            allowCredentials.add(Map.of(
                "type", "public-key",
                "id", Base64UrlUtil.encodeToString(auth.getCredentialId())
            ));
        }
        
        logger.info("Allow credentials count: {}", allowCredentials.size());
        
        if (allowCredentials.isEmpty()) {
            logger.error("No authenticators found for user: {}", username);
            return ResponseEntity.badRequest().body(Map.of("error", "No authenticators found for user"));
        }
        
        Map<String, Object> response = new HashMap<>();
        response.put("challenge", challengeB64);
        response.put("timeout", 60000);
        response.put("rpId", "localhost");
        response.put("allowCredentials", allowCredentials);
        response.put("userVerification", "required");
        
        logger.info("Authentication response: {}", response);
        logger.info("=== END BEGIN AUTHENTICATION ===");
        
        return ResponseEntity.ok(response);
    }
    
    @PostMapping("/authenticate/finish")
    public ResponseEntity<?> finishAuthentication(@RequestBody Map<String, Object> request) {
        try {
            logger.info("=== FINISH AUTHENTICATION ===");
            logger.info("Request received: {}", request);
            
            String username = (String) request.get("username");
            String storedChallenge = challengeStore.get(username);
            
            logger.info("Username: {}", username);
            logger.info("Stored challenge found: {}", storedChallenge != null);
            
            if (storedChallenge == null) {
                logger.error("Challenge not found for user: {}", username);
                return ResponseEntity.badRequest().body(Map.of("error", "Challenge not found"));
            }
            
            
            Map<String, Object> credential = (Map<String, Object>) request.get("credential");
            String credentialId = (String) credential.get("id");
            Map<String, Object> response = (Map<String, Object>) credential.get("response");
            String clientDataJSON = (String) response.get("clientDataJSON");
            String authenticatorData = (String) response.get("authenticatorData");
            String signature = (String) response.get("signature");
            
            logger.info("Credential ID: {}", credentialId);
            logger.info("Client data JSON length: {}", clientDataJSON != null ? clientDataJSON.length() : "null");
            logger.info("Authenticator data length: {}", authenticatorData != null ? authenticatorData.length() : "null");
            logger.info("Signature length: {}", signature != null ? signature.length() : "null");
            
            
            Optional<Authenticator> authOpt = authenticatorRepository.findByCredentialId(Base64UrlUtil.decode(credentialId));
            logger.info("Authenticator found: {}", authOpt.isPresent());
            
            if (authOpt.isEmpty()) {
                logger.error("Authenticator not found for credential ID: {}", credentialId);
                return ResponseEntity.badRequest().body(Map.of("error", "Authenticator not found"));
            }
            
            Authenticator authenticator = authOpt.get();
            logger.info("Found authenticator: ID={}, SignCount={}, User={}", 
                       authenticator.getId(), authenticator.getSignCount(), authenticator.getUser().getUsername());
            
            
            try {
                Base64UrlUtil.decode(clientDataJSON);
                Base64UrlUtil.decode(authenticatorData);
                Base64UrlUtil.decode(signature);
                logger.info("Base64 validation successful");
            } catch (Exception e) {
                logger.error("Base64 validation failed: {}", e.getMessage());
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid authentication data"));
            }
            
            
            long oldSignCount = authenticator.getSignCount();
            authenticator.setSignCount(oldSignCount + 1);
            authenticatorRepository.save(authenticator);
            logger.info("Updated sign count from {} to {}", oldSignCount, authenticator.getSignCount());
            
            challengeStore.remove(username);
            logger.info("Removed challenge for user: {}", username);
            
            logger.info("=== AUTHENTICATION SUCCESSFUL ===");
            return ResponseEntity.ok(Map.of(
                "status", "ok", 
                "user", username,
                "message", "Authentication successful"
            ));
            
        } catch (Exception e) {
            logger.error("Authentication failed with exception: ", e);
            return ResponseEntity.badRequest().body(Map.of("error", "Authentication failed: " + e.getMessage()));
        }
    }
    
 @GetMapping("/users")
    public ResponseEntity<?> getUsers() {
        List<User> users = userRepository.findAll();
        List<Map<String, Object>> userList = new ArrayList<>();
        
        for (User user : users) {
            Map<String, Object> userMap = new HashMap<>();
            userMap.put("id", user.getId());
            userMap.put("username", user.getUsername());
            userMap.put("authenticatorCount", user.getAuthenticators().size());
            userList.add(userMap);
        }
        
        return ResponseEntity.ok(userList);
    }
    
}