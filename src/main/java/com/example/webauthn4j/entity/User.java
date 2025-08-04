package com.example.webauthn4j.entity;


import jakarta.persistence.*;
import java.util.List;

@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true, nullable = false)
    private String username;
    
    @Column(nullable = false)
    private byte[] userHandle;
    
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Authenticator> authenticators;
    
    // Constructors
    public User() {}
    
    public User(String username, byte[] userHandle) {
        this.username = username;
        this.userHandle = userHandle;
    }
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public byte[] getUserHandle() { return userHandle; }
    public void setUserHandle(byte[] userHandle) { this.userHandle = userHandle; }
    
    public List<Authenticator> getAuthenticators() { return authenticators; }
    public void setAuthenticators(List<Authenticator> authenticators) { this.authenticators = authenticators; }
}