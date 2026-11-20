# AndesShield v2 — Plataforma Full-Stack de Matriz de Riesgos de Ciberseguridad

**AndesShield** es una plataforma web multi-organización de gestión de riesgos de ciberseguridad con **arquitectura híbrida**:
- **Modo Full-Stack Empresarial (Docker):** Backend en **Rust (Edition 2024, `#![forbid(unsafe_code)]`)** con **Axum 0.8**, **SQLx 0.9**, **Argon2id 0.6** y **PostgreSQL 18**, con autenticación por cookies `HttpOnly + SameSite=Strict`, aislamiento *multi-tenant*, control de acceso basado en roles (**RBAC**), *rate limiting* y **bitácora de auditoría inmutable (`ISO/IEC 27001:2022 A.8.15`)**.
- **Modo Estático Zero-Dependency (Cloudflare Pages):** La misma interfaz (`index.html`, sin librerías externas) detecta automáticamente si la API Rust está disponible; en hosting estático opera de forma autónoma con persistencia local (`localStorage`) y exportación/importación portátil JSON/CSV/PDF.

Diseñada con controles alineados a **ISO/IEC 27001:2022**, **CIS AWS Benchmark**, **OWASP Top 10**, **Ley 21.663** (Marco de Ciberseguridad de Chile) y **Ley 21.719** (Protección de Datos Personales).

- **Demo estática (Cloudflare Pages):** https://matriz-riesgo-victormanzano.pages.dev
- **Repositorio:** https://github.com/V333I/matriz-riesgo-VM
- **Autor:** Víctor Manzano

---

## Stack Tecnológico (Últimas Versiones Estables)

| Capa | Tecnología | Versión |
| :--- | :--- | :--- |
| **Backend** | Rust (`edition = "2024"`, `rust:1-bookworm`) | `1.100+` |
| **Framework HTTP** | `axum` + `tokio` + `tower-http` | `0.8` / `1.54+` / `0.7` |
| **Base de Datos** | PostgreSQL (`postgres:18-alpine`) + `sqlx` | `18` / `0.9` |
| **Criptografía / Auth** | `argon2` (`Argon2id v19`) + `sha2` + `rand` | `0.6` / `0.10` / `0.9` |
| **Frontend** | Single-file HTML5 / CSS3 / Vanilla JS (0 dependencias) | Nativo |
| **Contenedores** | Docker Multi-Stage + Docker Compose (`read_only`, non-root) | `compose.yaml` |

---

## Arquitectura del Proyecto

```text
.
├── index.html                  # Frontend híbrido (detecta automáticamente /api/v1/health)
├── _headers                    # Cabeceras OWASP para Cloudflare Pages
├── compose.yaml                # Orquestación Docker endurecida (PostgreSQL 18 + Rust API)
├── .env.example                # Plantilla de variables de entorno
└── backend/
    ├── Dockerfile              # Build multi-stage (rust:1-bookworm → debian:bookworm-slim non-root)
    ├── Cargo.toml              # Dependencias Rust Edition 2024
    ├── migrations/
    │   └── 0001_init.sql       # Esquema: users, sessions, organizations, memberships, risks, audit_logs
    └── src/
        ├── main.rs             # Servidor Axum, middleware de cabeceras OWASP, límites y graceful shutdown
        ├── auth.rs             # Argon2id v19, sesiones 256-bit (SHA-256 en BD), HttpOnly cookies, RBAC
        ├── models.rs           # DTOs tipados, validación estricta y motor de cálculo R = P × I
        ├── rate_limit.rs       # Rate limiter por IP (ventana deslizante anti fuerza bruta)
        ├── routes.rs           # API REST /api/v1/* (auth, orgs, risks, import, reset, audit)
        └── seed.rs             # Inicialización idempotente (admin inicial + caso CoopAndes Digital)
```

---

## Seguridad y Endurecimiento (OWASP & Contenedores)

- **Seguridad de memoria:** `#![forbid(unsafe_code)]` en todo el backend Rust.
- **Autenticación y Gestión de Cuenta:** Contraseñas hasheadas con **Argon2id v19** y verificación anti-enumeración por tiempo constante; tokens de sesión CSPRNG de 256 bits almacenados únicamente como hash **SHA-256** en PostgreSQL y enviados en cookies `HttpOnly; SameSite=Strict`; menú de usuario para editar perfil, cambiar contraseña (con revocación automática de otras sesiones) y revocar sesiones activas.
- **Cero credenciales hardcodeadas (`CWE-798`):** Todas las claves y secretos se configuran vía `.env` (excluido del repositorio mediante `.gitignore`).
- **Aislamiento Multi-Tenant y RBAC:** Cada consulta valida membresía y rol (`admin`, `analyst`, `viewer`) en `memberships`, previniendo *IDOR / BOLA* (`OWASP API1:2023`).
- **Protección contra Fuerza Bruta e Inyección:** *Rate limiting* estricto en `/api/v1/auth/*` (15 req/min por IP), límite de payload de `2 MiB`, consultas 100% parametrizadas (`SQLx`), escapado XSS y neutralización contra **CSV / Formula Injection (`CWE-1236`)**.
- **Auditoría ISO/IEC 27001:2022 (A.8.15):** Registro inmutable en `audit_logs` de inicios de sesión, creación/edición/eliminación de organizaciones y riesgos, e importaciones JSON.
- **Contenedores endurecidos:** Imagen runtime mínima sin compilador, usuario sin privilegios (`uid 10001`), sistema de archivos `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges:true`, healthcheck nativo en el binario (`--healthcheck`) y PostgreSQL 18 aislado en red interna sin puertos expuestos al host.
- **Cabeceras HTTP OWASP:** `Content-Security-Policy` estricta, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `COOP` y `CORP`.

---

## Ejecución Rápida con Docker (Sin instalar Rust ni PostgreSQL en el PC)

1. Clona el repositorio, crea tu archivo `.env` a partir de `.env.example` y define tus contraseñas seguras (`POSTGRES_PASSWORD` y opcionalmente `SEED_ADMIN_*`):
   ```bash
   git clone https://github.com/V333I/matriz-riesgo-VM.git
   cd matriz-riesgo-VM
   cp .env.example .env
   ```
2. Levanta toda la plataforma con Docker Compose:
   ```bash
   docker compose up -d --build
   ```
3. Abre **http://localhost:8080** en tu navegador y selecciona **Crear Cuenta** (o inicia sesión con el administrador que hayas configurado en `.env`). La primera cuenta creada recibe automáticamente el caso demostrativo **CoopAndes Digital**.
4. Para detener y limpiar contenedores (sin dejar basura en el equipo):
   ```bash
   docker compose down        # Conserva los datos en el volumen Docker pgdata
   docker compose down -v     # Elimina también el volumen de base de datos
   ```

---

## Metodología y Validación QA (Escala 5×5)

El motor calcula $R = P \times I$ (escala `1–5`) en frontend y backend con los rangos: `1–5` **Bajo** (*Monitorear*), `6–9` **Medio** (*Mejorar controles*), `10–16` **Alto** (*Intervenir pronto*) y `17–25` **Crítico** (*Intervenir ya*).

| Probabilidad (`P`) | Impacto (`I`) | Resultado Esperado | Resultado Obtenido | Estado |
| :---: | :---: | :--- | :--- | :---: |
| `4` | `5` | `20 – Crítico` | `20 – Crítico` (*Intervenir ya*) | PASS |
| `2` | `3` | `6 – Medio` | `6 – Medio` (*Mejorar controles*) | PASS |
| `3` | `5` | `15 – Alto` | `15 – Alto` (*Intervenir pronto*) | PASS |
| `4` | `4` | `16 – Alto` | `16 – Alto` (*Intervenir pronto*) | PASS |
| `1` | `5` | `5 – Bajo` | `5 – Bajo` (*Monitorear*) | PASS |
