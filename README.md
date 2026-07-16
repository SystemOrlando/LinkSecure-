# LinkSecure

Herramienta para validar si un enlace es seguro antes de abrirlo. La idea nace de lo seguido que llegan links por correo o WhatsApp que terminan siendo phishing, y de que no hay una forma rápida de chequearlos sin depender de un solo servicio.

Analiza la URL con varios métodos a la vez (no solo uno) y da un veredicto con el detalle de cada chequeo, para que el usuario entienda por qué se marcó como sospechoso o no.

## Cómo valida

- **Blacklist**: lista negra local + TLDs con historial de abuso.
- **Heurísticas**: IPs literales en vez de dominio, uso de `@`, punycode, exceso de subdominios, palabras típicas de phishing, etc.
- **Reputación externa**: Google Safe Browsing y VirusTotal (si se configuran las API keys).
- **SSL/TLS**: si el certificado existe, es válido y no está por expirar.
- **WHOIS**: antigüedad del dominio (los dominios recién creados son mucho más riesgosos).

Con todo eso arma un score de 0 a 100 y un veredicto: Seguro, Sospechoso o Malicioso.

## Stack

- Backend: Python + FastAPI
- Frontend: Next.js + TypeScript + CSS + Tailwind
- Base de datos pensada: PostgreSQL (para cuando se agregue historial de análisis)

## Correr el proyecto

Backend:

```
cd LinkSecure
.venv\Scripts\python.exe -m uvicorn api.main:app --reload
```

Frontend:

```
cd LinkSecure/frontend
npm install
npm run dev
```

Por defecto el frontend pega contra `http://localhost:8000`. Se puede cambiar con la variable `NEXT_PUBLIC_API_URL`.

## Configuración opcional

Copiar `.env.example` a `.env` y llenar las keys si se quiere activar Safe Browsing / VirusTotal. Sin esas keys el análisis igual funciona, solo que ese método queda en warning.

## Pendiente

- Guardar historial de URLs analizadas
- Tests automatizados
- Deploy
