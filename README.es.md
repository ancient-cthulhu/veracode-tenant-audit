
# Auditoría de Tenant de Veracode

Script de auditoría **independiente y de solo lectura** para un tenant de Veracode. Ejecuta seis verificaciones independientes contra las APIs de Identidad y Aplicaciones y produce evidencias en CSV por verificación, además de un informe HTML consolidado adecuado para auditorías de cumplimiento.

## Qué audita

| # | Verificación | Qué verifica | Dominio |
|---|---|---|---|
| 1 | **Modelo de Identidad** | Cada usuario tiene un `user_id` GUID inmutable distinto del email/nombre de usuario. Evidencia empírica de que la autorización no depende de atributos mutables. | Gestión de Identidad |
| 2 | **RBAC** | Distribución de roles, proporción de Administradores (mínimo privilegio), privilegios de cuentas de servicio API, conflictos de Segregación de Funciones (SoD). | Mínimo Privilegio / SoD |
| 3 | **Segregación por Equipos** | Aplicaciones sin asignación de equipo, con severidad especial para apps de criticidad de negocio ALTA/MUY_ALTA. | Segregación de Acceso |
| 4 | **Usuarios Privilegiados y Cuentas Obsoletas** | Usuarios privilegiados activos para validación RACI, cuentas sin inicio de sesión en N días, inventario de cuentas deshabilitadas. | Ciclo de Vida de Cuentas |
| 5 | **Trazabilidad** | Inventario de capacidades de auditoría disponibles vs. brechas. Indica si se ejecutó la verificación 7. | Auditoría y Trazabilidad |
| 6 | **Hardening de Cuenta** | Cobertura de restricción por IP, cobertura de SAML SSO vs. autenticación local. | Fortaleza de Autenticación |
| 7 | **Detección de Deriva de Identidad** *(opt‑in)* | Detecta cambios de identidad por UID comparando con un snapshot de una ejecución previa: cambios de campos (email/nombre), ciclo de vida (añadido/eliminado/reactivado/desactivado), transiciones de privilegios, colisiones de nombre de usuario, colisiones de email, cambios de email entre dominios, y cambios de email en cuentas privilegiadas. Requiere `--enable-change-detection`. | Integridad de Identidad |

## Requisitos

- Python 3.9+
- Cuenta de servicio API de Veracode con rol **Admin API**
- Credenciales HMAC: `API ID` y `API KEY`

## Instalación

```bash
pip install -r requirements.txt
````

## Credenciales

Opción A — variables de entorno:

```bash
export VERACODE_API_KEY_ID="..."
export VERACODE_API_KEY_SECRET="..."
```

Opción B — `~/.veracode/credentials`:

```ini
[default]
veracode_api_key_id = ...
veracode_api_key_secret = ...
```

## Uso

```bash
# Región comercial (predeterminada)
python veracode_tenant_audit.py --output ./audit_output

# Región europea
python veracode_tenant_audit.py --region european --output ./audit_output

# Región federal
python veracode_tenant_audit.py --region federal --output ./audit_output

# Umbral de obsolescencia personalizado (90 días por defecto)
python veracode_tenant_audit.py --stale-days 60

# Omitir inventario de aplicaciones (más rápido)
python veracode_tenant_audit.py --skip-apps

# Habilitar verificación 7: detectar cambios de email/nombre por UID vía diff de snapshot
# La primera ejecución crea la línea base; las siguientes detectan cambios
python veracode_tenant_audit.py --enable-change-detection

# Ubicación personalizada de snapshots (para ejecuciones compartidas/programadas)
python veracode_tenant_audit.py --enable-change-detection --snapshot-dir /var/lib/veracode-audit
```

## Categorías de deriva (verificación 7)

| Categoría                  | Severidad   | Qué detecta                                                                                                                                                        |
| -------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `username_collisions`      | **Crítico** | El `user_name` actual aparece bajo un UID distinto al anterior. Veracode indica que los nombres de usuario no se reciclan; si ocurre, escalar de inmediato.        |
| `privileged_email_changes` | **Alta**    | Cambio de email en una cuenta con roles de Administrador, Líder de Seguridad u otros roles privilegiados.                                                          |
| `privilege_acquired`       | **Alta**    | El UID obtuvo estatus de rol privilegiado desde el último snapshot.                                                                                                |
| `email_collisions`         | **Alta**    | El mismo email en 2+ cuentas humanas o 2+ cuentas de servicio API. Un humano emparejado con su propia cuenta API (patrón intencional de Veracode) **no** se marca. |
| `cross_domain_emails`      | **Alta**    | El cambio de email cruzó de dominio organizacional (p. ej., `@corp.com` → `@gmail.com`).                                                                           |
| `field_changes`            | **Media**   | Cambios por campo en email, `user_name`, `first_name`, `last_name`. Nota: cambios de `user_name` no deberían aparecer; si aparecen, escalar.                       |
| `reactivated`              | **Media**   | Cuenta pasó de inactiva a activa.                                                                                                                                  |
| `privilege_lost`           | Informativa | El UID perdió estatus de rol privilegiado. Rutina, pero se registra.                                                                                               |
| `deactivated`              | Informativa | Señal rutinaria de baja.                                                                                                                                           |
| `added`                    | Informativa | Nuevos UID desde el último snapshot.                                                                                                                               |
| `removed`                  | Informativa | UID que ya no están presentes. Veracode no recicla nombres de usuario, por lo que es raro.                                                                         |

Cada categoría escribe su propio CSV (`07_<categoría>.csv`), de modo que incluso categorías vacías aportan evidencia explícita de “revisado, sin hallazgos” para la trazabilidad de la auditoría.

## Historial de hallazgos

Cada ejecución persiste hallazgos accionables (Crítico, Alto, Medio, Bajo) en `findings_history.jsonl` dentro del directorio de snapshots. El panel “Actividad reciente” del informe HTML muestra estos hallazgos históricos agrupados por fecha de ejecución, permitiendo ver la actividad de varias semanas sin abrir informes antiguos.

Configure la ventana de retrospectiva con `--history-window-days` (por defecto 56 = 8 semanas). El archivo JSONL crece de forma append‑only y no se depura automáticamente; rotarlo o archivarlo externamente si es necesario (permanece pequeño — \~200 bytes por hallazgo).

Los hallazgos informativos no se persisten en el historial para mantener el panel enfocado en señales accionables. Aun así, aparecen en el informe HTML y CSV de la ejecución actual.

```bash
# Por defecto: mostrar las últimas 8 semanas en el HTML
python veracode_tenant_audit.py --enable-change-detection

# Mostrar los últimos 6 meses
python veracode_tenant_audit.py --enable-change-detection --history-window-days 180
```

El archivo de historial vive en el mismo `--snapshot-dir` que el snapshot de estado de usuarios, por lo que basta con mantener un único directorio persistente entre ejecuciones.

## Programación de la verificación 7

La verificación 7 está diseñada para ejecución periódica. El snapshot se persiste entre ejecuciones y cada ejecución reporta el delta. **Cadencia recomendada: diaria**; semanal es aceptable, pero aumenta el punto ciego intra‑ventana para patrones de cambio y reversión.

Ejemplo de entrada cron (diaria a las 02:00):

    0 2 * * * cd /opt/veracode-audit && python veracode_tenant_audit.py --enable-change-detection --snapshot-dir /var/lib/veracode-audit --output ./reports/$(date +\%Y-\%m-\%d)

Los N snapshots previos se rotan automáticamente bajo `--snapshot-dir` como `users_snapshot.<timestamp>.json`, permitiendo comparar múltiples ejecuciones para forense si es necesario.

## Salidas

Todos los archivos se escriben en el directorio indicado por `--output`:

| Archivo                                   | Contenido                                                                                     |
| ----------------------------------------- | --------------------------------------------------------------------------------------------- |
| `veracode_tenant_audit.html`              | Informe consolidado con resumen ejecutivo y hallazgos ordenados por severidad                 |
| `findings.json`                           | Todos los hallazgos en JSON estructurado (listo para SIEM/ingesta)                            |
| `01_identity_model.csv`                   | Inventario completo de usuarios con verificación UID vs email                                 |
| `02_rbac_all_users.csv`                   | Todos los usuarios con roles y equipos                                                        |
| `02_rbac_administrators.csv`              | Usuarios activos con rol de Administrador                                                     |
| `02_rbac_api_service_accounts.csv`        | Todas las cuentas de servicio API                                                             |
| `02_rbac_sod_conflicts.csv`               | Usuarios con combinaciones de roles en conflicto                                              |
| `02_rbac_role_distribution.json`          | Resumen de distribución de roles                                                              |
| `03_teams_inventory.csv`                  | Todos los equipos del tenant                                                                  |
| `03_applications_team_assignment.csv`     | Cada aplicación con su(s) equipo(s) y criticidad                                              |
| `03_applications_without_team.csv`        | Aplicaciones sin asignación de equipo                                                         |
| `04_privileged_users_active.csv`          | Usuarios activos con roles privilegiados                                                      |
| `04_orphan_no_roles.csv`                  | Cuentas activas sin roles asignados                                                           |
| `04_orphan_no_teams.csv`                  | Cuentas humanas activas sin pertenencia a equipos                                             |
| `04_login_disabled_active.csv`            | Cuentas activas con `login_enabled=false`                                                     |
| `04_disabled_accounts.csv`                | Cuentas inactivas/deshabilitadas                                                              |
| `05_traceability_capabilities.csv`        | Matriz de capacidades de auditoría vs brechas de la plataforma                                |
| `06_account_hardening.csv`                | Restricción por IP y tipo de autenticación por usuario                                        |
| `07_field_changes.csv`                    | *(solo verificación 7)* Cambios por campo vs snapshot previo, con valores antiguo/nuevo       |
| `07_added.csv`                            | *(solo verificación 7)* Nuevos UID desde el último snapshot                                   |
| `07_removed.csv`                          | *(solo verificación 7)* UID eliminados desde el último snapshot                               |
| `07_reactivated.csv`                      | *(solo verificación 7)* UID que pasaron de inactivos a activos                                |
| `07_deactivated.csv`                      | *(solo verificación 7)* UID que pasaron de activos a inactivos                                |
| `07_privilege_acquired.csv`               | *(solo verificación 7)* UID que obtuvieron roles privilegiados                                |
| `07_privilege_lost.csv`                   | *(solo verificación 7)* UID que perdieron roles privilegiados                                 |
| `07_username_collisions.csv`              | *(solo verificación 7)* `user_name` apareciendo bajo un UID distinto al previo                |
| `07_email_collisions.csv`                 | *(solo verificación 7)* Mismo email en 2+ humanos o 2+ APIs                                   |
| `07_cross_domain_emails.csv`              | *(solo verificación 7)* Cambios de email que cruzaron dominio                                 |
| `07_privileged_email_changes.csv`         | *(solo verificación 7)* Cambios de email en cuentas privilegiadas                             |
| `<snapshot-dir>/users_snapshot.json`      | *(solo verificación 7)* Línea base actual para la próxima ejecución                           |
| `<snapshot-dir>/users_snapshot.<ts>.json` | *(solo verificación 7)* Snapshots rotados de ejecuciones previas (se conservan los últimos 4) |

## Umbrales de severidad

| Condición                                              | Severidad |
| ------------------------------------------------------ | --------- |
| Usuarios sin UID inmutable                             | Alta      |
| Proporción de Administradores > 5% de usuarios activos | Alta      |
| Aplicaciones ALTA/MUY\_ALTA sin equipo                 | Alta      |
| Usuarios privilegiados inactivos 90+ días              | Alta      |
| Cuentas de servicio API con privilegios elevados       | Media     |
| Conflictos de Segregación de Funciones                 | Media     |
| Apps no críticas sin equipo                            | Media     |
| Usuarios estándar inactivos 90+ días                   | Media     |
| Brecha de registros de auditoría autoservicio          | Media     |
| Cobertura SAML < 80% de usuarios activos               | Media     |

Los umbrales se definen como constantes al inicio del script y pueden ajustarse por engagement.

## Limitaciones

La plataforma **no expone cambios en atributos de perfil (email, first\_name, last\_name, user\_name) vía la Reporting API ni interfaces estándar de consulta de auditoría**, por lo que no son recuperables directamente mediante reportes nativos.

Sin embargo, estos cambios existen internamente; simplemente no se publican a través de la capa de API consultable. Contacte a Soporte de Veracode para más información.

El informe de AUDITORÍA se limita a eventos como:

*   Actividad de autenticación (inicios de sesión, sesiones)
*   Cambios de autorización (roles, equipos, permisos)
*   Otros eventos de seguridad del plano de control

**No incluye mutaciones de perfil a nivel de campo** en su dataset consultable.

### Comportamiento de la verificación 7 (diff de snapshots)

La verificación 7 implementa un control compensatorio mediante **diferencias basadas en estado**:

*   Captura un snapshot completo del estado de usuarios en cada ejecución
*   Compara contra el snapshot previo en la siguiente ejecución
*   Reporta únicamente los deltas detectados entre ejecuciones

## Seguridad

*   Usa la implementación oficial HMAC `veracode-api-signing`. Las credenciales nunca se incrustan en el código.
*   Las credenciales API deben rotarse cada 90 días según la guía de Veracode.
*   No se persisten datos sensibles fuera del directorio especificado por `--output`.

## Códigos de salida

*   `0` — auditoría completada con éxito
*   `2` — `veracode-api-signing` no está instalado
*   Distinto de cero en errores de autenticación (401) o autorización (403) de la API de Veracode
