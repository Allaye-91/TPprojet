import time
from scapy.all import sniff, IP, TCP, UDP, ARP, Raw
from collections import Counter
import matplotlib.pyplot as plt
from fpdf import FPDF
import os

# 1. Capture du trafic
def capturer_paquets(interface="eth0", nombre=50):
    print(f"[*] Démarrage de la capture de {nombre} paquets sur {interface}...")
    # On capture 'nombre' paquets. 'prn' est une fonction optionnelle appelée à chaque paquet
    paquets = sniff(iface=interface, count=nombre)
    print(f"[*] Capture terminée.")
    return paquets


# 2. Statistiques des protocoles
def analyser_statistiques(paquets):
    compteur = Counter()
    for p in paquets:
        if p.haslayer(TCP):
            compteur['TCP'] += 1
        elif p.haslayer(UDP):
            compteur['UDP'] += 1
        elif p.haslayer(ARP):
            compteur['ARP'] += 1
        else:
            compteur['Autre'] += 1
    return compteur


# 3. Analyse de sécurité (Détection basique)
def analyser_securite(paquets):
    menaces = []
    for p in paquets:
        msg = None
        # Exemple simple : Détection de signatures SQL basiques dans la charge utile (Raw)
        if p.haslayer(Raw) and p.haslayer(IP):
            payload = str(p[Raw].load).lower()
            if "union select" in payload or "or 1=1" in payload:
                msg = f"ALERTE: Tentative SQL Injection détectée depuis {p[IP].src}"

        if msg:
            menaces.append(msg)
            bloquer_attaquant(p[IP].src)  # Appel de la fonction facultative
    return menaces


# 3b. Action facultative : Blocage (Simulation)
def bloquer_attaquant(ip_source):
    # Pour un vrai blocage, on utiliserait os.system avec iptables (Linux) ou netsh (Windows)
    # Ici, on simule pour éviter de casser ta config réseau par erreur.
    print(f"!!! ACTION DÉFENSIVE : Simulation du blocage de l'IP {ip_source} !!!")
    # Exemple réel (Linux) : os.system(f"iptables -A INPUT -s {ip_source} -j DROP")


# 4. Génération du graphique
def generer_graphique(stats):
    plt.figure(figsize=(6, 4))
    plt.bar(stats.keys(), stats.values(), color=['blue', 'green', 'red', 'gray'])
    plt.title("Répartition des Protocoles")
    plt.xlabel("Protocole")
    plt.ylabel("Nombre de paquets")
    plt.savefig("graphique_trafic.png")
    plt.close()


# 5. Création du rapport PDF
def creer_rapport_pdf(stats, menaces):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Rapport d'Analyse Réseau", ln=1, align='C')

    # Ajout du graphique
    pdf.image("graphique_trafic.png", x=50, y=30, w=100)
    pdf.ln(100)  # Saut de ligne après l'image

    # Ajout du tableau de stats
    pdf.cell(200, 10, txt="Statistiques des protocoles :", ln=1)
    for proto, count in stats.items():
        pdf.cell(200, 10, txt=f"- {proto} : {count} paquets", ln=1)

    # Ajout de l'analyse de sécurité
    pdf.ln(10)
    pdf.set_text_color(255, 0, 0) if menaces else pdf.set_text_color(0, 128, 0)
    statut = "MENACES DÉTECTÉES" if menaces else "Aucune menace détectée. Trafic légitime."
    pdf.cell(200, 10, txt=f"Statut Sécurité : {statut}", ln=1)

    for menace in menaces:
        pdf.cell(200, 10, txt=menace, ln=1)

    pdf.output("rapport_reseau.pdf")
    print("[*] Rapport PDF généré : rapport_reseau.pdf")


# --- Main ---
if __name__ == "__main__":
    # Remplace "Wi-Fi" ou "eth0" par le nom exact de ton interface
    # Utilise 'conf.iface' dans le shell scapy pour trouver le nom par défaut
    try:
        data = capturer_paquets(interface=None, nombre=20)  # None utilise l'interface par défaut
        stats = analyser_statistiques(data)
        menaces = analyser_securite(data)
        generer_graphique(stats)
        creer_rapport_pdf(stats, menaces)
    except PermissionError:
        print("Erreur : Ce script doit être lancé en tant qu'administrateur/root.")