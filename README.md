# AndesShield — Sistema de Matriz de Riesgos de Ciberseguridad (CoopAndes Digital)

Aplicación web estática desarrollada en un único archivo (`index.html`, HTML5 + CSS3 + JavaScript puro, **sin librerías externas ni backend**) para la gestión y priorización de riesgos de ciberseguridad en arquitecturas **Cloud** y **On-Premise** de la organización **CoopAndes Digital**.

- **Asignatura:** Diseño de Arquitectura de Redes Seguras
- **Sede:** La Serena — **Docente:** Daniel Ruz Moreno
- **Aprendizaje Esperado 3.1:** Diseño de arquitectura on-premise y on-cloud de seguridad TI con políticas y controles alineados a normas nacionales e internacionales (`ISO/IEC 27001:2022`, `CIS Controls`, `Ley 21.663` Marco de Ciberseguridad y `Ley 21.719` Protección de Datos Personales).

---

## Integrante

- **Modalidad:** Individual
- **Autor:** Víctor Manzano

## URL Publicada (Cloudflare Pages)

- **Sitio en producción:** `https://matriz-riesgo-victormanzano.pages.dev`
- **Repositorio GitHub:** `https://github.com/V333I/matriz-riesgo-VM`

---

## Escala de Referencia Aplicada

El sistema calcula el riesgo mediante la fórmula $R = P \times I$ con escala de `1` a `5` en Probabilidad (`P`) e Impacto (`I`):

| Nivel de Riesgo | Rango ($R = P \times I$) | Color | Acción Recomendada |
| :--- | :---: | :---: | :--- |
| **Bajo** | `1 – 5` | Verde | Monitorear |
| **Medio** | `6 – 9` | Amarillo | Mejorar controles |
| **Alto** | `10 – 16` | Naranjo | Intervenir pronto |
| **Crítico** | `17 – 25` | Rojo | Intervenir ya |

---

## Registro de Validación (Casos de Prueba)

Se validó el algoritmo `clasificarRiesgo(P, I)` tanto de forma manual como mediante el módulo integrado **"Validación QA"** dentro de la aplicación:

| Probabilidad (P) | Impacto (I) | Resultado Esperado | Resultado Obtenido / Corrección | Estado |
| :---: | :---: | :--- | :--- | :---: |
| `4` | `5` | `20 – Crítico` | `20 – Crítico` (Acción: *Intervenir ya*). Sin errores. | PASS |
| `2` | `3` | `6 – Medio` | `6 – Medio` (Acción: *Mejorar controles*). Sin errores. | PASS |
| `3` | `5` | `15 – Alto` | `15 – Alto` (Acción: *Intervenir pronto*). Sin errores. | PASS |
| `4` | `4` | `16 – Alto` | `16 – Alto` (Acción: *Intervenir pronto*). Sin errores. | PASS |
| `1` | `5` | `5 – Bajo` | `5 – Bajo` (Acción: *Monitorear*). Sin errores. | PASS |

### Notas sobre validación y control de calidad
- Se verificaron explícitamente los valores frontera entre niveles (`5 → Bajo`, `6 → Medio`, `9 → Medio`, `10 → Alto`, `16 → Alto`, `17 → Crítico`), asegurando que no existan solapamientos ni errores de tipo `>` vs `>=`.
- Se validó que el campo **Fuente del dato** sea obligatorio en el formulario y bloquee el guardado si está vacío.
- Se verificó que los 6 hallazgos de CoopAndes Digital carguen automáticamente al abrir la URL pública en cualquier navegador (precargados en el estado inicial), además de persistir modificaciones locales en `localStorage`.

---

## Componente Creativo (Mejoras Implementadas)

Para diferenciar la solución se incorporaron las siguientes mejoras propias (100% nativas sin librerías externas):

1. **Identidad Visual Propia (AndesShield · CoopAndes Digital):** Logotipo SVG personalizado (escudo + cordillera), paleta corporativa, diseño adaptable y **selector de Modo Oscuro / Modo Claro** persistente.
2. **Panel Ejecutivo de KPIs y Gráficos SVG Nativos:** Tarjetas resumen por nivel de riesgo (inherente y residual), porcentaje global de reducción de riesgo, **gráfico de dona SVG** con selector Inherente/Residual y **gráfico de barras comparativo** antes vs. después del control.
3. **Matriz de Calor 5×5 Interactiva con Vista Dual:** Permite alternar entre *Riesgo Inherente*, *Riesgo Residual* y *Antes vs. Después* lado a lado. Al hacer clic en cualquier ID (`R-01`..`R-06`) se abre un modal con el desglose completo.
4. **Catálogo de Amenazas con Sugerencia Automática ISO/IEC 27001:2022:** Selector predefinido de amenazas cloud y on-premise que sugiere controles técnicos/normativos alineados a ISO/IEC 27001:2022, CIS AWS Benchmark y legislación chilena (Ley 21.663 y Ley 21.719).
5. **Filtros Avanzados, Búsqueda y Ordenamiento Dinámico:** Búsqueda en tiempo real, filtros por nivel de riesgo y entorno (`Cloud` / `On-Premise` / `Híbrido`) y ordenamiento interactivo por columnas.
6. **Persistencia, Exportación CSV/JSON e Impresión PDF:** Guardado automático en `localStorage`, exportación a **CSV con BOM UTF-8** (compatible con Excel), exportación e importación de **respaldos portátiles JSON** por empresa y estilos `@media print` optimizados para exportar a PDF.
7. **Módulo Integrado de Validación QA:** Botón **Validación QA** en la barra superior que ejecuta en vivo los 5 casos de prueba exigidos por la rúbrica.
8. **Soporte Multi-Organización (Multi-Empresa):** Barra superior para crear, renombrar, eliminar y alternar entre múltiples empresas independientes (manteniendo **CoopAndes Digital** como caso base precargado por defecto).
9. **Alertas y Diálogos Estilo SweetAlert2 Nativos:** Motor propio de diálogos de confirmación y notificaciones *toast* con íconos SVG animados, sin librerías externas.

---

## Resumen de Hallazgos — Caso CoopAndes Digital

| ID | Hallazgo / Activo | Entorno | Riesgo Inherente ($P \times I$) | Control Propuesto (Resumen) | Riesgo Residual ($P' \times I'$) | Reducción |
| :---: | :--- | :---: | :---: | :--- | :---: | :---: |
| **R-01** | Bucket S3 de respaldos con acceso público de lectura | Cloud | **25 – Crítico** ($5 \times 5$) | S3 Block Public Access, IAM mínimo privilegio, SSE-KMS, AWS Config (ISO 27001 A.5.15, A.8.24) | **3 – Bajo** ($1 \times 3$) | **-22 pts (-88%)** |
| **R-02** | Security Group con SSH (22) y RDP (3389) abiertos a `0.0.0.0/0` | Cloud | **20 – Crítico** ($5 \times 4$) | Cerrar `0.0.0.0/0`, usar AWS SSM Session Manager o VPN + MFA (ISO 27001 A.8.20, A.8.22) | **3 – Bajo** ($1 \times 3$) | **-17 pts (-85%)** |
| **R-03** | Cuenta root sin MFA utilizada por tres personas | Cloud | **20 – Crítico** ($4 \times 5$) | MFA hardware FIDO2, custodia break-glass, usuarios IAM individuales con RBAC (ISO 27001 A.5.17, A.8.5) | **4 – Bajo** ($1 \times 4$) | **-16 pts (-80%)** |
| **R-04** | Base de datos del portal con IP pública y almacenamiento sin cifrar | Cloud | **20 – Crítico** ($4 \times 5$) | Subred privada sin IP pública, cifrado AES-256 (KMS) en reposo y TLS 1.3 (ISO 27001 A.8.20, A.8.24) | **4 – Bajo** ($1 \times 4$) | **-16 pts (-80%)** |
| **R-05** | Ausencia de registro de actividad en la nube | Cloud | **12 – Alto** ($3 \times 4$) | AWS CloudTrail multi-región + Object Lock, VPC Flow Logs y SIEM (ISO 27001 A.8.15, A.8.16; Ley 21.663) | **3 – Bajo** ($1 \times 3$) | **-9 pts (-75%)** |
| **R-06** | Rack on-premise sin control de acceso y respaldos sin pruebas de restauración | On-Premise | **12 – Alto** ($3 \times 4$) | Acceso físico tarjeta/biometría + CCTV, respaldos 3-2-1-1-0 y pruebas trimestrales RTO/RPO (ISO 27001 A.7.2, A.8.13) | **6 – Medio** ($2 \times 3$) | **-6 pts (-50%)** |

---

## Pauta para Socialización (2 minutos) y Reflexión Grupal

- **Riesgo más crítico detectado:** **R-01 (Bucket S3 de respaldos con acceso público, $R = 25$ — Crítico)**, dado que combina exposición directa a escaneos automatizados constantes ($P=5$) con una potencial fuga masiva de respaldos históricos de socios y sanción legal bajo la Ley 21.719 ($I=5$).
- **Hallazgo que más redujo su nivel tras aplicar el control:** **R-01**, pasando de **25 (Crítico)** a **3 (Bajo)** (una reducción de **22 puntos / 88%**, descendiendo tres niveles completos al habilitar *S3 Block Public Access* y cifrado KMS).
- **Reflexión sobre el uso de IA:** Al generar sistemas de seguridad con IA es fundamental validar los límites exactos de la escala (por ejemplo, que `16` siga siendo *Alto* y `17` sea *Crítico*, y que `5` sea *Bajo* y `6` sea *Medio*), asegurar que los datos no dependan exclusivamente de `localStorage` para que sean visibles en la URL pública de Cloudflare Pages, y contrastar las fuentes de datos y controles con estándares vigentes (`ISO/IEC 27001:2022`, `CIS Benchmark` y `Ley 21.663`).
