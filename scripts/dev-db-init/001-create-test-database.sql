-- Development bootstrap for the JAWAKER dev database.
-- Runs only on first container start (docker-entrypoint-initdb.d).
-- Creates the isolated database used by integration tests so tests never
-- operate against the development database.

CREATE DATABASE jawaker_test OWNER jawaker;
