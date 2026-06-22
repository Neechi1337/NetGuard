# NetGuard - Script de Estudo para Detecção de ARP Spoofing 🛡️

O **NetGuard** é um script experimental em Python desenvolvido para fins de estudo e aprendizado em segurança de redes (Camada 2). O objetivo do projeto foi entender na prática como funciona o protocolo ARP, como ocorrem os ataques de Man-in-the-Middle (MitM) por envenenamento de cache e como criar uma lógica simples de automação de defesa.

---

## 🔍 Como Ele Funciona (E suas Limitações)

O script monitora o tráfego da rede local buscando pacotes ARP de resposta (`ARP Reply`). 

1. **Mapeamento Inicial:** Ao iniciar, ele descobre o MAC atualmente associado ao gateway enviando uma requisição ARP legítima.
2. **Monitoramento:** Ele fica ouvindo a rede. Se aparecer um pacote ARP dizendo que o IP do roteador pertence a outro MAC, ele assume que é um ataque.
3. **Tentativa de Mitigação:** O script envia uma pequena rajada de 5 pacotes legítimos em broadcast para tentar reverter o envenenamento na máquina local.

### ⚠️ Limitações Conhecidas (Por que não é uma ferramenta comercial):
* **Condição de Corrida (Race Condition):** Se a rede já estiver envenenada *antes* do script ser iniciado, ele vai registrar o MAC do atacante como legítimo e a defesa falhará.
* **Falta de Persistência:** Uma rajada de 5 pacotes limpa o cache momentaneamente, mas se o atacante estiver em um loop agressivo, ele voltará a envenenar a rede logo em seguida.
* **Dependência de Privilégios:** Precisa ser rodado como Administrador/Root para conseguir interagir com os pacotes de rede.

---

## 🚀 Tecnologias e Bibliotecas

* **Python 3.14**
* **Scapy** (Utilizado para captura e injeção de pacotes)
* **Threading** (Para não travar a captura principal enquanto envia a resposta)
