package com.example.auditlogserviceapp.dto;

import java.util.Map;

public record AuditEventInput(
        String eventType,      // e.g., "USER_LOGIN", "RECORD_VIEWED"
        String actorId,        // Who initiated the event
        String resourceType,   // e.g., "ACCOUNT_DATA"
        String resourceId,     // The targeted account identifier
        String tenantId,       // Enforces strict multi-tenant data isolation boundaries
        Map<String, Object> payload, // Dynamic custom metadata attributes
        Long timestamp         // Optional caller-supplied timestamp
) {}