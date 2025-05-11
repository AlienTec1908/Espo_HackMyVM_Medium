# Espo - HackMyVM (Medium)

![Espo.png](Espo.png)

## Übersicht

*   **VM:** Espo
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Espo)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 30. März 2024
*   **Original-Writeup:** https://alientec1908.github.io/Espo_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war die Kompromittierung der virtuellen Maschine "Espo" auf der HackMyVM-Plattform, um sowohl die User- als auch die Root-Flag zu erlangen. Der Weg begann mit einer Web-Enumeration, die durch Path Traversal ein verstecktes Verzeichnis `/_oldsite/` und darin eine `backup.zip`-Datei aufdeckte. Die Analyse des Backups lieferte Administrator-Zugangsdaten für die EspoCRM-Anwendung. Eine bekannte RCE-Schwachstelle (CVE-2023-5966) in der installierten EspoCRM-Version wurde genutzt, um initialen Zugriff als `www-data` zu erhalten. Die Rechteausweitung auf den Benutzer `mandie` erfolgte durch Ausnutzung eines Cronjobs, der Dateien aus einem global beschreibbaren Verzeichnis kopierte, in Kombination mit einer `.forward`-Datei zur Codeausführung. Schließlich wurden Root-Rechte durch eine unsichere `sudo`-Konfiguration für den Befehl `savelog` erlangt.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `vi` / `nano`
*   `nikto`
*   `dirb`
*   `gobuster`
*   `ffuf`
*   `curl`
*   `wget`
*   `unzip`
*   `cat`
*   Web Browser
*   CVE-2023-5966 Exploit (GitHub PoC)
*   `nc (netcat)`
*   `stty`
*   `ls`, `cd`, `id`
*   `ss`
*   `touch`
*   `sleep`
*   `chmod`
*   `mail`
*   `sudo`
*   `savelog`
*   `ssh-keygen` (obwohl nicht zwingend notwendig für den finalen Exploit)
*   `cp`
*   Standard Linux-Befehle

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Espo" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration:**
    *   IP-Findung mittels `arp-scan` (192.168.2.111), Hostname `espo.hmv` in `/etc/hosts` eingetragen.
    *   Umfassender Portscan mit `nmap` identifizierte offene Ports: 22/tcp (OpenSSH 9.2p1 Debian) und 80/tcp (Nginx, EspoCRM).

2.  **Web Enumeration & Path Traversal:**
    *   `nikto`, `dirb` und `gobuster` identifizierten Standard-Pfade der EspoCRM-Installation (`/admin`, `/install`, `/api`, etc.) und PHP 8.2.7.
    *   `ffuf` mit Path Traversal (`/admin../_FUZZ`) entdeckte ein verstecktes Verzeichnis `/_oldsite/`.
    *   Ein `gobuster`-Scan auf `/_oldsite/` fand eine `backup.zip`-Datei.

3.  **Initial Access (EspoCRM RCE via CVE-2023-5966):**
    *   Die `backup.zip` wurde heruntergeladen und entpackt. Die Datei `data/config.php` enthielt SMTP-Zugangsdaten (`admin` / `39Ue4kcVJ#YpaAV24CNmbWU`).
    *   Mit diesen Zugangsdaten wurde erfolgreich in das EspoCRM-Admin-Panel eingeloggt. Die Version wurde als 7.2.4 identifiziert.
    *   Recherche ergab die RCE-Schwachstelle CVE-2023-5966 (Extension Upload) für diese Version.
    *   Ein PoC von GitHub wurde verwendet, um eine präparierte Erweiterung hochzuladen, die eine Webshell (`/webshell.php`) installierte.
    *   Über die Webshell wurde eine Netcat-Reverse-Shell als Benutzer `www-data` aufgebaut.

4.  **Post-Exploitation / Privilege Escalation (von `www-data` zu `mandie`):**
    *   Enumeration ergab einen Benutzer `mandie` und ein Skript `/home/mandie/copyPics`.
    *   Das Verzeichnis `/var/shared_medias` war für `www-data` beschreibbar.
    *   Tests zeigten, dass das `copyPics`-Skript periodisch als `mandie` lief und nicht-ausführbare Dateien aus `/var/shared_medias` in ihr Home-Verzeichnis kopierte.
    *   Eine `.forward`-Datei (`|/dev/shm/pwn`) wurde in `/var/shared_medias` erstellt. Ein Skript `/dev/shm/pwn` (ausführbare Reverse Shell) wurde ebenfalls erstellt.
    *   Nachdem `copyPics` die `.forward`-Datei kopiert hatte, wurde eine E-Mail an `mandie` gesendet. Der lokale MTA verarbeitete die `.forward`-Datei und führte das Skript `/dev/shm/pwn` als `mandie` aus, was zu einer Shell als `mandie` führte. Die User-Flag wurde gelesen.

5.  **Privilege Escalation (von `mandie` zu root):**
    *   `sudo -l` für `mandie` zeigte: `(ALL : ALL) NOPASSWD: /usr/bin/savelog`.
    *   Der Befehl `sudo /usr/bin/savelog -x "bash" test` wurde verwendet, um eine Bash-Shell als `root` zu starten.
    *   Die Root-Flag wurde im Home-Verzeichnis von Root gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Path Traversal / Directory Bypass:** Eine Schwachstelle in der Webserver-Konfiguration oder Anwendung, die es erlaubte, über `../` aus einem Verzeichniskontext auszubrechen und auf eigentlich nicht direkt erreichbare Verzeichnisse (`/_oldsite/`) zuzugreifen.
*   **Information Disclosure (Backup-Datei im Web-Root):** Eine `backup.zip`-Datei mit Anwendungsquellcode und Konfigurationsdateien (inkl. Zugangsdaten) war öffentlich zugänglich.
*   **Bekannte CVE Ausnutzung (EspoCRM CVE-2023-5966):** Eine bekannte RCE-Schwachstelle in der installierten EspoCRM-Version ermöglichte das Hochladen einer bösartigen Erweiterung und somit Codeausführung als Webserver-Benutzer (`www-data`).
*   **Unsicherer Cronjob & Schreibberechtigungen:** Ein Cronjob (`copyPics`) kopierte Dateien aus einem für alle beschreibbaren Verzeichnis (`/var/shared_medias`) in das Home-Verzeichnis eines Benutzers (`mandie`). Dies ermöglichte das Einschleusen von Dateien.
*   **`.forward`-Missbrauch für Codeausführung:** Durch das Einschleusen einer `.forward`-Datei in das Home-Verzeichnis des Zielbenutzers und das Senden einer E-Mail konnte der lokale Mail Transfer Agent (MTA) dazu gebracht werden, ein beliebiges Skript als dieser Benutzer auszuführen.
*   **Unsichere `sudo`-Konfiguration (`savelog` NOPASSWD):** Dem Benutzer `mandie` wurde erlaubt, den Befehl `savelog` als `root` ohne Passworteingabe auszuführen. `savelog` kann missbraucht werden, um Befehle auszuführen (z.B. über die Option `-x`), was zur Erlangung einer Root-Shell führte.

## Flags

*   **User Flag (`/home/mandie/user.txt`):** `b462a4ac056477047a56ea23e6bbce19`
*   **Root Flag (`/root/root.txt`):** `0f4580e1632070ea32ead6334c0527c4`

## Tags

`HackMyVM`, `Espo`, `Medium`, `PathTraversal`, `BackupExposure`, `CVE-2023-5966`, `EspoCRM`, `RCE`, `CronjobExploitation`, `ForwardFile`, `SudoSavelog`, `Linux`, `Web`, `Privilege Escalation`
