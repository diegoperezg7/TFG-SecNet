# 🔐 SecNet: Sistema de Respuesta y Análisis Forense Automatizado

**SecNet** es un sistema automatizado de detección, respuesta y análisis forense ante incidentes de seguridad en red. Ha sido desarrollado como parte del Trabajo de Fin de Grado del ciclo de Administración de Sistemas Informáticos en Red (ASIR).

## 🧠 Descripción General

SecNet permite detectar tráfico malicioso en tiempo real usando **Suricata** como motor IDS/IPS, automatizar respuestas con scripts en Python, y realizar un análisis forense básico a través de una interfaz web intuitiva. Todo el sistema está contenerizado con **Docker** y preparado para entornos educativos o de pequeñas empresas con recursos limitados.

## ⚙️ Arquitectura del Proyecto

📁 suricata/ → Contiene configuración y reglas IPS personalizadas
📁 python-responder/ → Script de respuesta automática a alertas
📁 logs/ → Logs generados por Suricata (eve.json, suricata.log)
📁 database/ → Base de datos SQLite con alertas procesadas
📁 web-interface/ → Interfaz web para visualizar y gestionar alertas
docker-compose.yml → Orquestación completa del sistema con Docker


## 🚀 Componentes Principales

- **Suricata**: IDS/IPS en modo `af-packet`, detecta y bloquea tráfico malicioso.  
- **Responder.py**: Script en Python que analiza `eve.json`, almacena alertas en SQLite y ejecuta acciones.  
- **Interfaz web (PHP + JS)**: Permite visualizar alertas, bloquear IPs y hacer seguimiento.  
- **Docker**: Entorno auto-contenido y portable para ejecutar el sistema fácilmente.

## 📦 Requisitos

- Docker y Docker Compose instalados  
- Sistema Linux (recomendado para pruebas: Kali o Debian/Ubuntu)  
- Interfaz de red activa (por defecto se usa `eth0`, ajustable en `suricata.yaml`)

## 🛠️ Instalación

git clone https://github.com/tu-usuario/SecNet.git
cd SecNet
sudo docker-compose up --build
⚠️ Es necesario ejecutar con privilegios (por ejemplo, sudo) debido al modo IPS.

## 📈 Ejemplo de Uso
Lanza el sistema con Docker

Realiza un escaneo desde otra máquina (por ejemplo, nmap, hping3 o curl con patrones sospechosos)

El sistema detectará el tráfico, lo bloqueará (si corresponde) y generará alertas

Accede a la interfaz web en http://localhost:8080 para ver las alertas y tomar decisiones

## 📄 Funcionalidades Clave
✅ Detección de amenazas en tiempo real
✅ Bloqueo automático con reglas Suricata (drop)
✅ Registro forense en base de datos
✅ Interfaz web para gestionar alertas
✅ Arquitectura modular y portable (Docker)

## 🧪 Pruebas Recomendadas
bash
Copiar
Editar
nmap -sS 192.168.x.x          # Escaneo SYN
hping3 --flood -S -p 80 ...   # Ataque DoS simple
curl http://ip/etc/passwd     # Petición sospechosa
Verifica que las alertas se generen y aparezcan en la interfaz.

## 🛡️ Objetivo del Proyecto
Demostrar cómo una solución basada en código abierto puede ofrecer detección, respuesta y análisis forense básico en un entorno controlado y con recursos reducidos.

## 🧑‍💻 Autor
Diego Pérez García
