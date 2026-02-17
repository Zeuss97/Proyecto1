# Registro de IPs con monitoreo de ping

Aplicación web para:

- Registrar direcciones IP y monitorear ping cada 30 minutos.
- Editar datos de cada host (nombre, tipo, ubicación, alias y notas).
- Consultar historial de intentos de ping de los últimos 7 días por cada IP.
- Acceso con usuarios y roles (`admin` / `operator`).
- Gestión interna de usuarios desde un panel admin.
- Perfil de usuario para actualizar nombre, apellido, userID y foto (URL).

## Requisitos

- Python 3.10+
- Dependencias de `requirements.txt`

## Instalación

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Ejecución

```bash
python app.py
```

Disponible en `http://localhost:5000`.

## Acceso inicial demo

- Usuario: `admin`
- Contraseña: `admin`

Ese usuario demo se crea automáticamente al iniciar (si no existe) y puedes desactivarlo con:

```bash
DEMO_ADMIN_ENABLED=0 python app.py
```

## Roles

- **Admin**
  - Puede crear y eliminar usuarios.
  - Puede editar cualquier usuario (rol, userID, nombre, apellido, foto y contraseña opcional).
  - Puede registrar nuevas IPs.
- **Operador**
  - Puede consultar y modificar IPs existentes.
  - No puede crear/eliminar usuarios ni registrar IPs nuevas.

## Personalizar fondo del login

Coloca tu imagen en:

- `static/login-background.jpg`

## Notas

- En Windows se usa `ping -a`.
- En Linux/macOS se usa `ping -c 1` y DNS inversa.
- El ping automático corre cada 30 minutos (`PING_INTERVAL_SECONDS = 30 * 60`).
- Cada intento de ping queda guardado y se conserva por 7 días (`PING_LOG_RETENTION_DAYS`).
