# 🔐 Parcial 2 - Criptografía | Uninorte

**Ingeniería de Sistemas y Computación - Universidad del Norte**  
**Criptografía - 2025-I**  
**Grupo:** Nilson Hasbun, David Maury, Luis Rodríguez

---

## 🧠 Descripción del Proyecto

Este repositorio contiene el desarrollo completo del **Parcial 2 de Criptografía**, cuyo objetivo es implementar, analizar y atacar esquemas criptográficos modernos en escenarios reales de comunicación cliente-servidor.

Se abordan **3 escenarios** con un enfoque práctico en **intercambio de llaves**, **cifrado simétrico y asimétrico**, y **análisis de seguridad** mediante herramientas como **Wireshark** y técnicas como **ataques de hombre en el medio** y **resolución del logaritmo discreto**.

---

## 🚀 Escenarios Implementados

### 🔹 Escenario 1: Diffie-Hellman sobre 𝔽𝑝∗ con ChaCha20
- Intercambio de llaves usando Diffie-Hellman clásico.
- Derivación de clave simétrica con SHA-256.
- Cifrado de mensajes con **ChaCha20**.
- Ataque con algoritmo **Baby-step Giant-step** para romper la clave compartida.

### 🔹 Escenario 2: ECDH sobre Curva P-256 con Ataque MitM
- Intercambio de llaves usando ECC (P-256).
- Derivación de clave simétrica para cifrado con **AES-192 CBC**.
- Implementación de un **ataque MitM completo**: el atacante establece claves distintas con cliente y servidor y modifica los mensajes.

### 🔹 Escenario 3: Comparación Criptografía Simétrica vs Asimétrica
- Implementación de comunicaciones asimétricas con:
  - **RSA-OAEP**
  - **ElGamal (simulado con ECIES)**
- Comparación de eficiencia frente a:
  - **ChaCha20 (Escenario 1)**
  - **AES-192 CBC (Escenario 2)**
- Métricas: tiempo de cifrado/descifrado y tamaño promedio transmitido.

---

## 🧪 Resultados y Evidencia

🔬 El informe en LaTeX incluye:
- Capturas de **Wireshark**.
- Fragmentos del código clave.
- Comparación de rendimiento entre esquemas.
- Respuestas justificadas a preguntas de análisis de seguridad.
- Recomendaciones técnicas para entornos reales.

---

## 📁 Estructura del Proyecto

```bash
.
├── Escenario1
│   ├── attacker.py
│   ├── cliente.py
│   ├── diffiHellman.py
│   ├── parameters.json
│   └── server.py
├── Escenario2
│   ├── attacker.py
│   ├── cliente.py
│   └── server.py
├── Escenario3
│   ├── ElGamal.py
│   ├── indice.py
│   ├── Rsa.py
│   └── Servidor
│       └── servidor.py
└── README.md
