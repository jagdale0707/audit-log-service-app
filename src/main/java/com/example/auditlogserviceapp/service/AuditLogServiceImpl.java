package com.example.auditlogserviceapp.service;

import com.example.auditlogserviceapp.dto.AuditEventInput;
import com.example.auditlogserviceapp.dto.AuditRecord;
import com.example.auditlogserviceapp.dto.ExportBundle;
import com.example.auditlogserviceapp.dto.VerificationResult;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;

@Service
public class AuditLogServiceImpl implements AuditLogService {
    private final List<AuditRecord> ledger = new CopyOnWriteArrayList<>();
    private final ReentrantReadWriteLock rwLock = new ReentrantReadWriteLock();
    private final ObjectMapper mapper = new ObjectMapper();

    private final String genesisParentHash = "0".repeat(64);
    private final KeyPair asymmetricKeyPair;

    public AuditLogServiceImpl() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            this.asymmetricKeyPair = keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed initializing RSA cryptographic subsystem", e);
        }
    }

    private String computeSha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 hash algorithm unreachable", e);
        }
    }

    private String calculateFieldHash(String key, Object value, String salt) {
        try {
            String serializedValue = mapper.writeValueAsString(value);
            return computeSha256(key + "||" + serializedValue + "||" + salt);
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize field value payload", e);
        }
    }

    public String calculatePayloadRootHash(Map<String, String> commitments) {
        List<String> sortedKeys = commitments.keySet().stream().sorted().toList();
        StringBuilder combinedBytes = new StringBuilder();
        for (String key : sortedKeys) {
            combinedBytes.append(key).append(":").append(commitments.get(key));
        }
        return computeSha256(combinedBytes.toString());
    }

    public String calculateRecordHash(AuditRecord r) {
        String payloadRoot = calculatePayloadRootHash(r.getPayloadCommitments());
        String metaString = r.getIndex() + "||" + r.getEventType() + "||" + r.getActorId() + "||" +
                r.getResourceType() + "||" + r.getResourceId() + "||" + r.getTenantId() + "||" +
                r.getTimestamp() + "||" + r.getParentHash() + "||" + payloadRoot;
        return computeSha256(metaString);
    }

    // SCENARIO A: Concurrent Append-Only Block Write Operation
    public AuditRecord logEvent(AuditEventInput input) {
        rwLock.writeLock().lock();
        try {
            long index = ledger.size();
            String parentHash = (index == 0) ? genesisParentHash : ledger.get((int) index - 1).getRecordHash();
            long timestamp = (input.timestamp() != null) ? input.timestamp() : System.currentTimeMillis();

            AuditRecord record = new AuditRecord();
            record.setId(UUID.randomUUID().toString());
            record.setIndex(index);
            record.setEventType(input.eventType());
            record.setActorId(input.actorId());
            record.setResourceType(input.resourceType());
            record.setResourceId(input.resourceId());
            record.setTenantId(input.tenantId());
            record.setTimestamp(timestamp);
            record.setParentHash(parentHash);

            if (input.payload() != null) {
                for (Map.Entry<String, Object> entry : input.payload().entrySet()) {
                    String salt = UUID.randomUUID().toString().replace("-", "");
                    String fHash = calculateFieldHash(entry.getKey(), entry.getValue(), salt);
                    record.getPayloadCommitments().put(entry.getKey(), fHash);
                    record.getPayloadData().put(entry.getKey(), entry.getValue());
                    record.getPayloadSalts().put(entry.getKey(), salt);
                }
            }

            record.setRecordHash(calculateRecordHash(record));
            ledger.add(record);
            return record;
        } finally {
            rwLock.writeLock().unlock();
        }
    }

    // SCENARIO A: Multi-index Lookup Pipeline with Pagination
    public List<AuditRecord> queryEvents(String tenantId, String actorId, String resourceType, String resourceId, String eventType, Long fromTime, Long toTime, int page, int limit) {
        rwLock.readLock().lock();
        try {
            return ledger.stream()
                    .filter(r -> r.getTenantId().equals(tenantId))
                    .filter(r -> actorId == null || r.getActorId().equals(actorId))
                    .filter(r -> resourceType == null || r.getResourceType().equals(resourceType))
                    .filter(r -> resourceId == null || r.getResourceId().equals(resourceId))
                    .filter(r -> eventType == null || r.getEventType().equals(eventType))
                    .filter(r -> fromTime == null || r.getTimestamp() >= fromTime)
                    .filter(r -> toTime == null || r.getTimestamp() <= toTime)
                    .skip((long) (page - 1) * limit)
                    .limit(limit)
                    .collect(Collectors.toList());
        } finally {
            rwLock.readLock().unlock();
        }
    }

    // SCENARIO A & B: Unified Resilient Chain Verification
    public VerificationResult verifyChain() {
        rwLock.readLock().lock();
        try {
            if (ledger.isEmpty()) {
                return new VerificationResult(true, null, "NONE", "Ledger is empty.");
            }

            for (int i = 0; i < ledger.size(); i++) {
                AuditRecord current = ledger.get(i);

                // 1. Reverify block hash integrity
                if (!current.getRecordHash().equals(calculateRecordHash(current))) {
                    return new VerificationResult(false, current.getIndex(), "HASH_MISMATCH", "Local data corruption at index: " + current.getIndex());
                }

                // 2. Validate hash linkage
                if (i > 0) {
                    AuditRecord previous = ledger.get(i - 1);
                    if (!current.getParentHash().equals(previous.getRecordHash())) {
                        return new VerificationResult(false, current.getIndex(), "CHAIN_BREAK", "Link broken between index " + previous.getIndex() + " and " + current.getIndex());
                    }
                } else if (!current.isPrunedGenesis() && !current.getParentHash().equals(genesisParentHash)) {
                    return new VerificationResult(false, 0L, "PRUNED_INTEGRITY_VIOLATION", "Root baseline anchor block parent reference mismatch.");
                }
            }
            return new VerificationResult(true, null, "NONE", "Ledger chain fully intact.");
        } finally {
            rwLock.readLock().unlock();
        }
    }

    // SCENARIO B: Precision Data Redaction Framework
    public boolean redactPayloadField(long recordIndex, String targetKey) {
        rwLock.writeLock().lock();
        try {
            if (recordIndex < 0 || recordIndex >= ledger.size()) return false;
            AuditRecord r = ledger.get((int) recordIndex);

            if (!r.getPayloadCommitments().containsKey(targetKey)) return false;

            // Atomically erase dynamic parameters while preserving original payload commitment verification values
            r.getPayloadData().remove(targetKey);
            r.getPayloadSalts().remove(targetKey);
            return true;
        } finally {
            rwLock.writeLock().unlock();
        }
    }

    // SCENARIO B: Advanced Retention Optimization
    public int applyRetentionPolicy(long olderThanTimestamp) {
        rwLock.writeLock().lock();
        try {
            int itemsRemoved = 0;
            while (!ledger.isEmpty() && ledger.getFirst().getTimestamp() < olderThanTimestamp) {
                ledger.removeFirst();
                itemsRemoved++;
            }
            if (itemsRemoved > 0 && !ledger.isEmpty()) {
                ledger.getFirst().setPrunedGenesis(true);
            }
            return itemsRemoved;
        } finally {
            rwLock.writeLock().unlock();
        }
    }

    // SCENARIO B: Non-Repudiation Signed Bulk Export Bundles
    public ExportBundle exportResourceBundle(String tenantId, String resourceId) {
        rwLock.readLock().lock();
        try {
            List<AuditRecord> collection = ledger.stream()
                    .filter(r -> r.getTenantId().equals(tenantId) && r.getResourceId().equals(resourceId))
                    .collect(Collectors.toList());

            long exportedAt = System.currentTimeMillis();
            String payloadToSign = exportedAt + "||" + collection.size();

            Signature privateSignature = Signature.getInstance("SHA256withRSA");
            privateSignature.initSign(asymmetricKeyPair.getPrivate());
            privateSignature.update(payloadToSign.getBytes(StandardCharsets.UTF_8));
            String signatureHex = Base64.getEncoder().encodeToString(privateSignature.sign());

            return new ExportBundle(exportedAt, collection, signatureHex);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate secure compliance export bundle", e);
        } finally {
            rwLock.readLock().unlock();
        }
    }
}
