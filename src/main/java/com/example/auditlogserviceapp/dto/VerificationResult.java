package com.example.auditlogserviceapp.dto;

public record VerificationResult( boolean isValid,
                                  Long firstInconsistentIndex,
                                  String violationType, // "HASH_MISMATCH", "CHAIN_BREAK", "PRUNED_INTEGRITY_VIOLATION", "NONE"
                                  String details) {
}
