package com.example.auditlogserviceapp.service;

import com.example.auditlogserviceapp.dto.AuditEventInput;
import com.example.auditlogserviceapp.dto.AuditRecord;
import com.example.auditlogserviceapp.dto.ExportBundle;
import com.example.auditlogserviceapp.dto.VerificationResult;

import java.util.List;

public interface AuditLogService {
    AuditRecord logEvent(AuditEventInput input);

    List<AuditRecord> queryEvents(String tenantId, String actorId, String resourceType, String resourceId, String eventType, Long fromTime, Long toTime, int page, int limit);

    VerificationResult verifyChain();

    boolean redactPayloadField(long index, String targetKey);

    int applyRetentionPolicy(long thresholdTime);

    ExportBundle exportResourceBundle(String tenantId, String resourceId);

   // void forceBackdoorTamper(int index, String key, String value);
}
