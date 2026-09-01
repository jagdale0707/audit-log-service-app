package com.example.auditlogserviceapp.dto;

import java.util.List;

public record ExportBundle(long exportedAt,
                           List<AuditRecord> records,
                           String cryptographicSignature) {
}
