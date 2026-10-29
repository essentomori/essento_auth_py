# Python Auth Guide

Basic authentication and authorization implementation examples in Python using FastAPI, Passlib and PyJWT.

## Structure

- main.py: REST API with token authentication and role check.
- auth_guide.py: core functions for hashing and tokens.

## Setup

```bash
pip install fastapi uvicorn passlib bcrypt python-jose
```

Run server:
```bash
uvicorn main:app --reload
```
