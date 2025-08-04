package com.example.webauthn4j.repository;


import  com.example.webauthn4j.entity.Authenticator;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface AuthenticatorRepository extends JpaRepository<Authenticator, Long> {
    Optional<Authenticator> findByCredentialId(byte[] credentialId);
}