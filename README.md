# AndesShield — Plataforma de Matriz de Riesgos de Ciberseguridad

**AndesShield** es una aplicación web estática multi-organización desarrollada en un único archivo (`index.html`, HTML5 + CSS3 + JavaScript vanilla, **sin dependencias externas ni backend**) para evaluar, priorizar y gestionar riesgos de ciberseguridad en arquitecturas **Cloud**, **On-Premise** e **Híbridas**.

Diseñada con controles de referencia alineados a estándares internacionales y normativa vigente: **ISO/IEC 27001:2022**, **CIS AWS Benchmark**, **Ley 21.663** (Marco de Ciberseguridad de Chile) y **Ley 21.719** (Protección de Datos Personales).

- **Sitio en producción (Cloudflare Pages):** https://matriz-riesgo-victormanzano.pages.dev
- **Repositorio:** https://github.com/V333I/matriz-riesgo-VM
- **Autor:** Víctor Manzano

---

## Características Principales

- **Arquitectura Zero-Dependency (Single-File):** Todo el sistema (interfaz, gráficos SVG, motor de cálculo y persistencia) reside en `index.html`, garantizando carga instantánea, operación offline y cero superficie de ataque por librerías de terceros.
- **Gestión Multi-Organización:** Permite crear, renombrar, eliminar y alternar entre múltiples espacios de trabajo independientes desde la barra superior, manteniendo un caso demostrativo precargado (`CoopAndes Digital`).
- **Panel Ejecutivo y Visualización Nativa:** KPIs de riesgo inherente y residual, porcentaje global de reducción, gráfico de dona SVG y barras comparativas *Antes vs. Después*.
- **Matriz de Calor 5×5 Interactiva:** Alterna entre *Riesgo Inherente*, *Riesgo Residual* y vista dual *Antes vs. Después* lado a lado, con inspección detallada por hallazgo.
- **Catálogo de Amenazas con Sugerencia ISO/IEC 27001:2022:** Asistente integrado con controles técnicos y organizacionales predefinidos para riesgos cloud y on-premise.
- **Portabilidad y Reportes:** Persistencia local (`localStorage`), exportación a **CSV con BOM UTF-8** (compatible con Excel), exportación e importación de respaldos **JSON** por empresa y estilos `@media print` para exportación a PDF.
- **Alertas y Diálogos Modernos:** Motor nativo estilo SweetAlert2 con íconos SVG animados, notificaciones *toast* y soporte completo para **Modo Oscuro / Modo Claro**.
- **Suite de Validación Integrada (QA):** Módulo en vivo para comprobar el motor de clasificación frente a casos frontera.

---

## Metodología de Cálculo de Riesgo

El motor calcula el nivel de riesgo mediante la fórmula $R = P \times I$ en escala de `1` a `5` para **Probabilidad (`P`)** e **Impacto (`I`)**, exigiendo justificación obligatoria mediante **Fuente del dato**:

| Nivel de Riesgo | Rango ($R = P \times I$) | Color | Acción Recomendada |
| :--- | :---: | :---: | :--- |
| **Bajo** | `1 – 5` | Verde | Monitorear |
| **Medio** | `6 – 9` | Amarillo | Mejorar controles |
| **Alto** | `10 – 16` | Naranjo | Intervenir pronto |
| **Crítico** | `17 – 25` | Rojo | Intervenir ya |

---

## Validación y Control de Calidad (QA)

Pruebas automatizadas ejecutadas sobre `clasificarRiesgo(P, I)` verificando rangos y valores frontera (`5 → Bajo`, `6 → Medio`, `16 → Alto`, `17 → Crítico`):

| Probabilidad (`P`) | Impacto (`I`) | Resultado Esperado | Resultado Obtenido | Estado |
| :---: | :---: | :--- | :--- | :---: |
| `4` | `5` | `20 – Crítico` | `20 – Crítico` (*Intervenir ya*) | PASS |
| `2` | `3` | `6 – Medio` | `6 – Medio` (*Mejorar controles*) | PASS |
| `3` | `5` | `15 – Alto` | `15 – Alto` (*Intervenir pronto*) | PASS |
| `4` | `4` | `16 – Alto` | `16 – Alto` (*Intervenir pronto*) | PASS |
| `1` | `5` | `5 – Bajo` | `5 – Bajo` (*Monitorear*) | PASS |

---

## Caso Demostrativo Precargado — CoopAndes Digital

La aplicación incluye precargado un escenario de referencia de arquitectura híbrida con 6 hallazgos priorizados y una reducción global de riesgo del **79%**:

| ID | Activo / Hallazgo | Entorno | Riesgo Inherente ($P \times I$) | Control Propuesto (Resumen) | Riesgo Residual ($P' \times I'$) | Reducción |
| :---: | :--- | :---: | :---: | :--- | :---: | :---: |
| **R-01** | Bucket S3 de respaldos con acceso público de lectura | Cloud | **25 – Crítico** ($5 \times 5$) | S3 Block Public Access, IAM mínimo privilegio, SSE-KMS, AWS Config (ISO 27001 A.5.15, A.8.24) | **3 – Bajo** ($1 \times 3$) | **-22 pts (-88%)** |
| **R-02** | Security Group con SSH (22) y RDP (3389) abiertos a `0.0.0.0/0` | Cloud | **20 – Crítico** ($5 \times 4$) | Cerrar `0.0.0.0/0`, usar AWS SSM Session Manager o VPN + MFA (ISO 27001 A.8.20, A.8.22) | **3 – Bajo** ($1 \times 3$) | **-17 pts (-85%)** |
| **R-03** | Cuenta root sin MFA compartida por tres operadores | Cloud | **20 – Crítico** ($4 \times 5$) | MFA hardware FIDO2, custodia break-glass, usuarios IAM individuales con RBAC (ISO 27001 A.5.17, A.8.5) | **4 – Bajo** ($1 \times 4$) | **-16 pts (-80%)** |
| **R-04** | Base de datos del portal con IP pública y almacenamiento sin cifrar | Cloud | **20 – Crítico** ($4 \times 5$) | Subred privada sin IP pública, cifrado AES-256 (KMS) en reposo y TLS 1.3 (ISO 27001 A.8.20, A.8.24) | **4 – Bajo** ($1 \times 4$) | **-16 pts (-80%)** |
| **R-05** | Ausencia de registro de actividad y auditoría en la nube | Cloud | **12 – Alto** ($3 \times 4$) | AWS CloudTrail multi-región + Object Lock, VPC Flow Logs y SIEM (ISO 27001 A.8.15, A.8.16; Ley 21.663) | **3 – Bajo** ($1 \times 3$) | **-9 pts (-75%)** |
| **R-06** | Rack on-premise sin control de acceso y respaldos sin pruebas de restauración | On-Premise | **12 – Alto** ($3 \times 4$) | Acceso físico tarjeta/biometría + CCTV, respaldos 3-2-1-1-0 y pruebas trimestrales RTO/RPO (ISO 27001 A.7.2, A.8.13) | **6 – Medio** ($2 \times 3$) | **-6 pts (-50%)** |

---

## Uso y Despliegue

### Ejecución local
No requiere instalación ni proceso de compilación. Basta con clonar el repositorio y abrir `index.html` directamente en cualquier navegador moderno:

```bash
git clone https://github.com/V333I/matriz-riesgo-VM.git
cd matriz-riesgo-VM
```

### Despliegue en Cloudflare Pages
- **Framework preset:** `None`
- **Build command:** *(vacío)*
- **Build output directory:** `/`
- **Production branch:** `main`
