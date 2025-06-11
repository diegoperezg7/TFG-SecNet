# 🔐 SecNet: Sistema de Respuesta y Análisis Forense Automatizado

**SecNet** es un sistema integral de detección, respuesta y análisis forense automatizado ante incidentes de seguridad en red. Desarrollado como Trabajo de Fin de Grado (TFG) para el ciclo de Administración de Sistemas Informáticos en Red (ASIR), demuestra cómo una solución basada en código abierto puede ofrecer protección activa y visibilidad forense en entornos controlados o educativos con recursos limitados.

---

## 🧠 Descripción General

SecNet permite detectar tráfico malicioso en tiempo real utilizando **Suricata** como motor IDS/IPS, automatiza la respuesta a incidentes mediante scripts en Python y facilita el análisis forense básico a través de una interfaz web intuitiva. Todo el sistema se ejecuta en contenedores **Docker**, simplificando su despliegue y portabilidad.

---

## 📸 Capturas de Pantalla

**Dashboard principal** – métricas clave (alertas totales, de alta gravedad, IPs bloqueadas, últimas 24h) + gráficas de distribución de tipos y gravedad

![Captura de pantalla 2025-06-07 102039](https://github.com/user-attachments/assets/6916ddce-7a1e-4c9d-b266-9e139544efc1)

**IPs Bloqueadas y Alertas Recientes** – continuación del dashboard para actuar de forma priorizada

![Captura de pantalla 2025-06-11 110600](https://github.com/user-attachments/assets/b60c0512-a487-4dca-8dd7-60ec2a90a41d)

**Listado de Alertas** – tabla filtrable por fecha, severidad, protocolo; acciones ver / bloquear

![Captura de pantalla 2025-06-07 102156](https://github.com/user-attachments/assets/6411225b-4565-43da-a42f-05c79157a3d8)

**Detalles Alerta Gravedad 3** – intento de fuerza bruta SSH bloqueado al instante

![Captura de pantalla 2025-06-11 110344](https://github.com/user-attachments/assets/fb773c7f-893e-4d26-ab22-753153a2e819)

**Detalles Alerta Gravedad 2** – escaneo SYN hacia HTTP detectado

![Captura de pantalla 2025-06-11 110217](https://github.com/user-attachments/assets/58c1cea7-4039-478e-84e7-23d9f33b6b1d)

**Detalles Alerta Gravedad 1** – ICMP benigno/ruidoso

![Captura de pantalla 2025-06-11 110035](https://github.com/user-attachments/assets/f386d9ed-84af-4c8c-8b49-9ce696d44dcc)

**Datos Completo en JSON** – datos crudos de Suricata (flow_id, payload, SID, etc.) para análisis forense

![Captura de pantalla 2025-06-11 110359](https://github.com/user-attachments/assets/87f1d9b9-ef38-4a60-bb46-774f4e3f399a)

---

## 🛑 Tabla de Severidad de Alertas

La severidad de cada alerta ayuda a priorizar la respuesta y el análisis. Los niveles son:

| Severidad/Gravedad                   | Nivel | Descripción                                                                                                                                   |
|--------------------------------------|-------|-----------------------------------------------------------------------------------------------------------------------------------------------|
| 🔴 Alta (Crítico)                    | 3     | Indica amenazas graves que requieren acción inmediata, ya que pueden comprometer la seguridad del sistema o la integridad de la red. <br>Ejemplos:<br>• SSH Brute Force Attempt<br>• SMB Enumeration Attempt<br>• Telnet Connection Attempt |
| 🟡 Media (Advertencia)               | 2     | Señales de actividad sospechosa o intentos de reconocimiento. Deben ser monitorizadas y pueden requerir intervención si se repiten.<br>Ejemplos:<br>• Nmap HTTP Scan<br>• High DNS Query Volume<br>• SSL/TLS Connection Attempt<br>• MS-SQL Connection Attempt<br>• MySQL Connection Attempt<br>• SMTP Connection Attempt<br>• SYN Scan to HTTP port |
| 🟢 Baja (Informativo)                | 1     | Actividad generalmente legítima o de bajo riesgo, útil para contexto o análisis de patrones. No requiere acción inmediata.<br>Ejemplo:<br>• ICMP Ping (Network Scan) |

> La clasificación automática de eventos permite una reacción eficiente y minimiza los falsos positivos.

---

## ⚙️ Arquitectura del Proyecto

- 📁 **suricata/**: Configuración y reglas IPS/IDS personalizadas
- 📁 **python-responder/**: Script de respuesta automática a alertas
- 📁 **logs/**: Almacén de logs generados por Suricata (`eve.json`, `suricata.log`)
- 📁 **database/**: Base de datos SQLite con alertas procesadas
- 📁 **web-interface/**: Interfaz web para visualizar y gestionar alertas
- `docker-compose.yml`: Orquestación completa del sistema mediante Docker

---

## 🚀 Componentes Principales

- **Suricata**: IDS/IPS que detecta y bloquea tráfico malicioso en modo `af-packet`
- **Responder.py**: Script en Python que analiza logs (`eve.json`), almacena alertas en SQLite y ejecuta respuestas automáticas (como bloqueo de IPs)
- **Interfaz web (PHP + JS)**: Permite visualizar alertas, bloquear IPs y hacer seguimiento de incidentes en tiempo real
- **Docker**: Facilita la ejecución portable y reproducible del sistema

---

## 📦 Requisitos

- Docker y Docker Compose instalados
- Sistema operativo Linux (recomendado: Kali, Debian o Ubuntu)
- Interfaz de red activa (por defecto `eth0`, configurable en `suricata.yaml`)
- Python 3.8+, PHP 7.4+, Suricata, SQLite3, iptables

---

## 🛠️ Instalación

```bash
git clone https://github.com/diegoperezg7/TFG-SecNet.git
cd TFG-SecNet
sudo docker-compose up --build
```

> ⚠️ Es necesario ejecutar con privilegios (por ejemplo, sudo) por el modo IPS.

También puedes instalar dependencias de forma manual si no usas Docker:

```bash
# Dependencias de Python
pip install -r requirements.txt

# Dependencias de PHP
composer install

# Configuración de Suricata
sudo cp suricata/rules/local.rules /etc/suricata/rules/
sudo systemctl restart suricata
```

---

## 📈 Ejemplo de Uso

1. Lanza el sistema con Docker o manualmente.
2. Realiza un escaneo desde otra máquina (por ejemplo, `nmap`, `hping3` o `curl` con patrones sospechosos).
3. El sistema detectará el tráfico, lo bloqueará (si corresponde) y generará alertas.
4. Accede a la interfaz web en [http://localhost:8080](http://localhost:8080) para visualizar las alertas y tomar decisiones.

---

## 📄 Funcionalidades Clave

✅ Detección de amenazas en tiempo real  
✅ Bloqueo automático de IPs maliciosas mediante reglas Suricata  
✅ Registro forense de eventos y ataques en base de datos  
✅ Interfaz web para gestionar y clasificar alertas  
✅ Arquitectura modular y portable (Docker)

---

## 🧪 Pruebas Recomendadas

Ejecuta los siguientes comandos desde otro host de la red para probar el sistema:

```bash
nmap -sS 192.168.x.x          # Escaneo SYN
hping3 --flood -S -p 80 ...   # Ataque DoS simple
curl http://ip/etc/passwd     # Petición sospechosa
```

Verifica que las alertas se generen y aparezcan en la interfaz web.

---

## 🛡️ Objetivo del Proyecto

Demostrar cómo una solución basada en código abierto puede ofrecer detección, respuesta y análisis forense básico en un entorno controlado y con recursos reducidos.

---

## 📝 Licencia

Este proyecto está bajo la Licencia MIT - consulta el archivo LICENSE para más detalles.

---

## 📫 Contacto

Diego Pérez García - @diegoperezg7

Mi perfil: https://github.com/diegoperezg7/
