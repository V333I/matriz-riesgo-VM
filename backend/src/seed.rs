use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::hash_password;

pub struct SeedRisk {
    pub code: &'static str,
    pub asset: &'static str,
    pub env: &'static str,
    pub threat: &'static str,
    pub vuln: &'static str,
    pub p: i16,
    pub i: i16,
    pub source: &'static str,
    pub control: &'static str,
    pub pr: i16,
    pub ir: i16,
}

pub fn coopandes_default_risks() -> Vec<SeedRisk> {
    vec![
        SeedRisk {
            code: "R-01",
            asset: "Bucket S3 de respaldos corporativos",
            env: "Cloud",
            threat: "Exfiltración masiva de respaldos y fuga de datos financieros/personales de socios",
            vuln: "Bucket S3 configurado con acceso público de lectura (ACL/política abierta sin Block Public Access)",
            p: 5,
            i: 5,
            source: "Verizon DBIR 2024 e IBM Cost of a Data Breach 2024 (misconfiguración cloud y escaneos automatizados continuos) + Auditoría AWS Security Hub CoopAndes Digital",
            control: "Activar AWS S3 Block Public Access a nivel de cuenta y bucket, revocar permisos públicos, aplicar IAM de mínimo privilegio, habilitar cifrado SSE-KMS y monitoreo continuo con AWS Config (ISO/IEC 27001:2022 A.5.15, A.8.24; CIS AWS 2.1.4; Ley 21.719).",
            pr: 1,
            ir: 3,
        },
        SeedRisk {
            code: "R-02",
            asset: "Servidores Cloud (EC2) y Security Group perimetral",
            env: "Cloud",
            threat: "Ataques automatizados de fuerza bruta, explotación remota y despliegue de ransomware",
            vuln: "Security Group con puertos administrativos SSH (22) y RDP (3389) abiertos a 0.0.0.0/0",
            p: 5,
            i: 4,
            source: "CISA & GreyNoise Threat Intelligence 2024 (intentos diarios activos contra puertos 22/3389 expuestos) + Revisión de reglas VPC CoopAndes Digital",
            control: "Eliminar reglas de entrada 0.0.0.0/0 en puertos 22 y 3389; migrar la administración a AWS Systems Manager Session Manager o VPN corporativa con MFA y bastion restringido por IP (ISO/IEC 27001:2022 A.8.20, A.8.22; CIS AWS 5.2 y 5.3).",
            pr: 1,
            ir: 3,
        },
        SeedRisk {
            code: "R-03",
            asset: "Cuenta Root de la infraestructura Cloud",
            env: "Cloud",
            threat: "Toma de control total de la nube (Account Takeover), eliminación de servicios o secuestro de cuenta",
            vuln: "Cuenta root sin autenticación multifactor (MFA) y compartida por tres personas sin trazabilidad",
            p: 4,
            i: 5,
            source: "Microsoft Digital Defense Report 2024 & Verizon DBIR 2024 (robo de credenciales sin MFA como vector crítico; MFA bloquea >99% de intrusiones automatizadas) + Revisión IAM CoopAndes Digital",
            control: "Activar MFA de hardware (FIDO2/YubiKey) en la cuenta root, rotar y custodiar la clave en bóveda de emergencia (break-glass), prohibir su uso diario y crear usuarios IAM individuales con MFA obligatorio y RBAC (ISO/IEC 27001:2022 A.5.17, A.8.2, A.8.5; CIS AWS 1.4 y 1.5).",
            pr: 1,
            ir: 4,
        },
        SeedRisk {
            code: "R-04",
            asset: "Base de datos del portal web de socios",
            env: "Cloud",
            threat: "Acceso directo no autorizado desde Internet, robo de credenciales/datos y lectura de snapshots sin cifrar",
            vuln: "Instancia de base de datos desplegada con IP pública y almacenamiento en reposo sin cifrar",
            p: 4,
            i: 5,
            source: "Cloud Security Alliance (CSA) Top Threats 2024 y OWASP Top 10 + Escaneo de superficie de ataque externa de CoopAndes Digital",
            control: "Reubicar la base de datos en subred privada sin IP pública (acceso exclusivo desde el Security Group de aplicación), habilitar cifrado en reposo AES-256 con KMS y cifrado en tránsito obligatorio TLS 1.3 (ISO/IEC 27001:2022 A.8.20, A.8.24; CIS AWS 2.3.1 y 2.3.3).",
            pr: 1,
            ir: 4,
        },
        SeedRisk {
            code: "R-05",
            asset: "Plano de control y servicios Cloud (IAM, VPC, S3, RDS)",
            env: "Cloud",
            threat: "Actividad maliciosa encubierta, escalación de privilegios no detectada e imposibilidad de auditoría forense",
            vuln: "Ausencia total de registro de actividad en la nube (CloudTrail, VPC Flow Logs y SIEM desactivados)",
            p: 3,
            i: 4,
            source: "IBM Cost of a Data Breach Report 2024 (tiempo medio de detección >190 días sin telemetría) y Ley 21.663 Marco de Ciberseguridad de Chile (obligación de trazabilidad y reporte al CSIRT Nacional)",
            control: "Activar AWS CloudTrail multi-región con validación de integridad y bucket S3 inmutable (Object Lock), habilitar VPC Flow Logs y centralizar alertas en SIEM con retención mínima de 1 año (ISO/IEC 27001:2022 A.8.15, A.8.16; CIS AWS 3.1).",
            pr: 1,
            ir: 3,
        },
        SeedRisk {
            code: "R-06",
            asset: "Rack On-Premise y respaldos locales",
            env: "On-Premise",
            threat: "Manipulación física no autorizada, robo de equipos y pérdida irreversible de datos ante fallas o ransomware",
            vuln: "Rack on-premise sin control de acceso físico y respaldos sin pruebas periódicas de restauración",
            p: 3,
            i: 4,
            source: "Veeam Data Protection Trends Report 2024 (fallos recurrentes en restauraciones no probadas) + Inspección física de sala de comunicaciones de CoopAndes Digital",
            control: "Implementar cerradura electrónica con tarjeta/biometría, bitácora y CCTV en sala de servidores; adoptar estrategia de respaldo 3-2-1-1-0 (copia inmutable/offline) y ejecutar simulacros trimestrales de restauración validando RTO/RPO (ISO/IEC 27001:2022 A.7.2, A.7.4, A.8.13).",
            pr: 2,
            ir: 3,
        },
    ]
}

pub async fn insert_coopandes_risks(
    pool: &PgPool,
    org_id: Uuid,
    actor_id: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    for r in coopandes_default_risks() {
        sqlx::query(
            r#"
            INSERT INTO risks
              (organization_id, code, asset, env, threat, vuln, p, i, source, control, pr, ir, created_by)
            VALUES
              ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            ON CONFLICT (organization_id, code) DO NOTHING
            "#,
        )
        .bind(org_id)
        .bind(r.code)
        .bind(r.asset)
        .bind(r.env)
        .bind(r.threat)
        .bind(r.vuln)
        .bind(r.p)
        .bind(r.i)
        .bind(r.source)
        .bind(r.control)
        .bind(r.pr)
        .bind(r.ir)
        .bind(actor_id)
        .execute(pool)
        .await?;
    }
    Ok(())
}

pub async fn seed_initial_data(pool: &PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let existing_users: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;

    if existing_users.0 > 0 {
        return Ok(());
    }

    let admin_name = std::env::var("SEED_ADMIN_NAME").unwrap_or_else(|_| "Víctor Manzano".to_string());
    let admin_email = std::env::var("SEED_ADMIN_EMAIL")
        .unwrap_or_else(|_| "admin@andesshield.local".to_string())
        .trim()
        .to_lowercase();
    let admin_password = std::env::var("SEED_ADMIN_PASSWORD")
        .unwrap_or_else(|_| "AndesShield#2026!".to_string());

    let pw_hash = hash_password(&admin_password)
        .map_err(|e| format!("No se pudo generar hash Argon2id inicial: {}", e.message))?;

    let user_id: (Uuid,) = sqlx::query_as(
        "INSERT INTO users (full_name, email, password_hash) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(&admin_name)
    .bind(&admin_email)
    .bind(&pw_hash)
    .fetch_one(pool)
    .await?;

    let org_id: (Uuid,) = sqlx::query_as(
        "INSERT INTO organizations (name, sector, is_default, created_by) VALUES ($1, $2, TRUE, $3) RETURNING id",
    )
    .bind("CoopAndes Digital")
    .bind("Cooperativa / Financiero")
    .bind(user_id.0)
    .fetch_one(pool)
    .await?;

    sqlx::query("INSERT INTO memberships (organization_id, user_id, role) VALUES ($1, $2, 'admin')")
        .bind(org_id.0)
        .bind(user_id.0)
        .execute(pool)
        .await?;

    insert_coopandes_risks(pool, org_id.0, Some(user_id.0)).await?;

    sqlx::query(
        r#"
        INSERT INTO audit_logs (organization_id, actor_user_id, actor_email, action, entity_type, entity_id, details)
        VALUES ($1, $2, $3, 'SYSTEM_SEED', 'organization', $4, '{"message": "Inicialización automática de CoopAndes Digital (6 hallazgos)"}'::jsonb)
        "#,
    )
    .bind(org_id.0)
    .bind(user_id.0)
    .bind(&admin_email)
    .bind(org_id.0.to_string())
    .execute(pool)
    .await?;

    tracing::info!(
        "Base de datos inicializada con administrador '{}' y organización demostrativa CoopAndes Digital.",
        admin_email
    );
    Ok(())
}
