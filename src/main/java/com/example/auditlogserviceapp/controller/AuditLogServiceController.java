package com.example.auditlogserviceapp.controller;

import com.example.auditlogserviceapp.dto.AuditEventInput;
import com.example.auditlogserviceapp.dto.AuditRecord;
import com.example.auditlogserviceapp.dto.ExportBundle;
import com.example.auditlogserviceapp.dto.VerificationResult;
import com.example.auditlogserviceapp.service.AuditLogService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/audit")
public class AuditLogServiceController {
    private final AuditLogService auditLogService;

    public AuditLogServiceController(AuditLogService engine) {
        this.auditLogService = engine;
    }

    @PostMapping("/log")
    public ResponseEntity<AuditRecord> logEvent(@RequestBody AuditEventInput input) {
        return ResponseEntity.ok(auditLogService.logEvent(input));
    }

    @GetMapping("/query")
    public ResponseEntity<List<AuditRecord>> queryEvents(
            @RequestHeader("X-Tenant-ID") String tenantId,
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String resourceType,
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) Long fromTime,
            @RequestParam(required = false) Long toTime,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "50") int limit) {
        return ResponseEntity.ok(auditLogService.queryEvents(tenantId, actorId, resourceType, resourceId, eventType, fromTime, toTime, page, limit));
    }

    @GetMapping("/verify")
    public ResponseEntity<VerificationResult> verifyChain() {
        return ResponseEntity.ok(auditLogService.verifyChain());
    }

    @PostMapping("/redact")
    public ResponseEntity<Map<String, Object>> redactField(
            @RequestParam long index,
            @RequestParam String targetKey) {
        boolean executed = auditLogService.redactPayloadField(index, targetKey);
        return ResponseEntity.ok(Map.of("index", index, "field", targetKey, "redacted", executed));
    }

    @PostMapping("/retention")
    public ResponseEntity<Map<String, Object>> applyRetention(@RequestParam long thresholdTime) {
        int removedCount = auditLogService.applyRetentionPolicy(thresholdTime);
        return ResponseEntity.ok(Map.of("prunedBlocksCount", removedCount, "status", "SUCCESS"));
    }

    @GetMapping("/export")
    public ResponseEntity<ExportBundle> exportBundle(
            @RequestHeader("X-Tenant-ID") String tenantId,
            @RequestParam String resourceId) {
        return ResponseEntity.ok(auditLogService.exportResourceBundle(tenantId, resourceId));
    }

    /*@PostMapping("/diagnostics/tamper")
    public ResponseEntity<String> injectTamper(
            @RequestParam int index,
            @RequestParam String key,
            @RequestParam String value) {
        auditLogService.forceBackdoorTamper(index, key, value);
        return ResponseEntity.ok("Tamper injected at index " + index);
    }*/
}
