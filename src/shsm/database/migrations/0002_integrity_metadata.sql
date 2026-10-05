-- Migration 0002: Add metadata_json column to integrity_baseline for structural diffing
ALTER TABLE integrity_baseline ADD COLUMN metadata_json TEXT;
