package com.example.webauthn4j.entity;


import com.webauthn4j.data.attestation.statement.AttestationStatement;

import jakarta.persistence.*;

@Entity
@Table(name = "authenticators")
public class Authenticator {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false)
    private byte[] credentialId;
    
    @Column(nullable = false)
    private byte[] publicKey;
    
    @Column(nullable = false)
    private long signCount;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;
    
    // Constructors
    public Authenticator() {}
    
    public Authenticator(byte[] credentialId, byte[] publicKey, long signCount, User user) {
        this.credentialId = credentialId;
        this.publicKey = publicKey;
        this.signCount = signCount;
        this.user = user;
    }
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public byte[] getCredentialId() { return credentialId; }
    public void setCredentialId(byte[] credentialId) { this.credentialId = credentialId; }
    
    public @io.micrometer.common.lang.Nullable byte[] getPublicKey() { return publicKey; }
    public void setPublicKey(byte[] publicKey) { this.publicKey = publicKey; }
    
    public long getSignCount() { return signCount; }
    public void setSignCount(long signCount) { this.signCount = signCount; }
    
    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }
}