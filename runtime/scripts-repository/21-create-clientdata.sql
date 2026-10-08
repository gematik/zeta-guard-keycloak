-- Prevent expiration of client data by inserting a record with a future last_access timestamp
INSERT INTO zeta_client_data (id, attestation_state, created_at, last_access) VALUES ('zeta-client', 'VALID', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '1 day');
