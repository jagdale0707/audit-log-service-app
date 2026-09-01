package com.example.auditlogserviceapp.dto;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class AuditRecord {
    private String id;
    private long index;
    private String eventType;
    private String actorId;
    private String resourceType;
    private String resourceId;
    private String tenantId;
    private long timestamp;

    // Cryptographic commitments and structural data storage mappings
    private Map<String, String> payloadCommitments = new ConcurrentHashMap<>(); // key -> individual field hash
    private Map<String, Object> payloadData = new ConcurrentHashMap<>();        // key -> raw value (purged on redaction)
    private Map<String, String> payloadSalts = new ConcurrentHashMap<>();       // key -> field salt (purged on redaction)

    private String parentHash;
    private String recordHash;
    private boolean isPrunedGenesis = false; // Indicates if this became a virtual anchor block due to pruning

    // Getters and Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public long getIndex() { return index; }
    public void setIndex(long index) { this.index = index; }
    public String getEventType() { return eventType; }
    public void setEventType(String eventType) { this.eventType = eventType; }
    public String getActorId() { return actorId; }
    public void setActorId(String actorId) { this.actorId = actorId; }
    public String getResourceType() { return resourceType; }
    public void setResourceType(String resourceType) { this.resourceType = resourceType; }
    public String getResourceId() { return resourceId; }
    public void setResourceId(String resourceId) { this.resourceId = resourceId; }
    public String getTenantId() { return tenantId; }
    public void setTenantId(String tenantId) { this.tenantId = tenantId; }
    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
    public Map<String, String> getPayloadCommitments() { return payloadCommitments; }
    public void setPayloadCommitments(Map<String, String> pc) { this.payloadCommitments = pc; }
    public Map<String, Object> getPayloadData() { return payloadData; }
    public void setPayloadData(Map<String, Object> pd) { this.payloadData = pd; }
    public Map<String, String> getPayloadSalts() { return payloadSalts; }
    public void setPayloadSalts(Map<String, String> ps) { this.payloadSalts = ps; }
    public String getParentHash() { return parentHash; }
    public void setParentHash(String parentHash) { this.parentHash = parentHash; }
    public String getRecordHash() { return recordHash; }
    public void setRecordHash(String recordHash) { this.recordHash = recordHash; }
    public boolean isPrunedGenesis() { return isPrunedGenesis; }
    public void setPrunedGenesis(boolean pg) { this.isPrunedGenesis = pg; }
}
