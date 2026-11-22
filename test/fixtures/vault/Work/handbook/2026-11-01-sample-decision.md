---
title: "Sample decision: fixture lock"
date: 2026-11-01
status: locked
locks:
  - fixture-lock-one
  - fixture-lock-two
source: synthetic fixture
tags:
  - ops
  - zeusi
related: ["[[Home]]", "[[wiki/glossary]]"]
---
# Sample decision

The fixture owner decided to keep the importer read-only. See [[wiki/glossary#Chunk]].

## Context

Importers mirror notes into the database and never write back. This paragraph is
stable across edits so its chunk keeps its vector.

## Ruling

Section that the edit test changes. Original wording.

### Follow-up

A third-level heading stays its own chunk with a nested heading path.
