import sys
import threading
from scapy.all import sniff, ARP, getmacbyip, get_working_if, conf, sendp, Ether

def obter_mac_legitimo(ip_gateway, interface):
    """Descobre o MAC Address real do roteador automaticamente."""
    print(f"[*] Buscando o MAC legítimo do roteador ({ip_gateway}) via {interface.description}...")
    mac = getmacbyip(ip_gateway) 
    
    if not mac:
        print(f"[-] Erro: Não foi possível obter o MAC do gateway {ip_gateway}.")
        sys.exit(1)
        
    print(f"[+] Roteador legítimo mapeado: {ip_gateway} -> {mac}")
    return mac

def mitigar_ataque(ip_gateway, mac_legitimo, interface):
    """Dispara pacotes ARP legítimos na Camada 2 para restaurar a rede sem warnings."""
    print(f"[🛡️] Defesa Ativa: Injetando pacotes ARP legítimos para limpar o envenenamento...")
    
    # Monta o frame perfeito na Camada 2 (Ethernet) em Broadcast
    pacote_defesa = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, 
        psrc=ip_gateway, 
        hwsrc=mac_legitimo, 
        pdst="255.255.255.255"
    )
    
    # Envia o pacote direto na Camada 2 usando a interface correta
    sendp(pacote_defesa, count=5, verbose=False, iface=interface)
    print(f"[✔] Tabela ARP restaurada com sucesso.")

def analisar_pacote_arp(packet, ip_gateway, mac_legitimo, interface):
    """Monitora as respostas ARP e ativa a defesa se detectar divergências."""
    if packet.haslayer(ARP) and packet[ARP].op == 2:  
        ip_origem = packet[ARP].psrc
        mac_origem = packet[ARP].hwsrc

        if ip_origem == ip_gateway:
            if mac_origem.lower() != mac_legitimo.lower():
                print("\n" + "!" * 60)
                print("[⚠️] ALERTA DE SEGURANÇA: ATAQUE ARP SPOOFING DETECTADO!")
                print(f"[!] O seu roteador ({ip_gateway}) está sendo clonado!")
                print(f"[!] MAC Real do Roteador: {mac_legitimo}")
                print(f"[!] MAC do Atacante: {mac_origem}")
                print("!" * 60)
                
                # Dispara a mitigação em background
                threading.Thread(
                    target=mitigar_ataque, 
                    args=(ip_gateway, mac_legitimo, interface), 
                    daemon=True
                ).start()
            else:
                print(f"[OK] Resposta ARP legítima do roteador ({ip_origem}).")

def iniciar_defesa():
    interface_ativa = get_working_if()
    ip_gateway = conf.route.route("0.0.0.0")[2]
    
    print(f"[+] Placa de rede detectada: {interface_ativa.description}")
    print(f"[+] Gateway padrão detectado: {ip_gateway}")
    print("-" * 50)
    
    mac_legitimo = obter_mac_legitimo(ip_gateway, interface_ativa)
    
    print(f"\n[*] NetGuard Ativo com Defesa Ativa! Monitorando... Pressione Ctrl+C para parar.\n")
    
    sniff(
        iface=interface_ativa, 
        filter="arp", 
        store=False, 
        prn=lambda pkt: analisar_pacote_arp(pkt, ip_gateway, mac_legitimo, interface_ativa)
    )

if __name__ == "__main__":
    try:
        iniciar_defesa()
    except KeyboardInterrupt:
        print("\n[*] Monitoramento encerrado pelo usuário.")