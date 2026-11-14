#!/bin/bash
# Démo guidée : lance le serveur, puis envoie un message avec chaque algorithme.
# Usage :  bash examples/demo.sh          (ou  PYTHON=/usr/bin/python3 bash examples/demo.sh)
cd "$(dirname "$0")/.." || exit 1
PY=${PYTHON:-python3}
PORT=5000
SERVER_PID=""

start_server() {  # $@ = options supplémentaires du serveur
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null
    $PY -u network/server.py --port $PORT "$@" &
    SERVER_PID=$!
    sleep 1
}
trap '[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null' EXIT

step() {  # affiche un titre et attend Entrée
    echo
    echo "=============================================================="
    echo "  $1"
    echo "=============================================================="
    read -r -p "[Entrée pour lancer] " _
}

run() {  # affiche la commande puis l'exécute
    echo "\$ $PY network/client.py $*"
    $PY network/client.py "$@" | cut -c1-230
    sleep 1
}

if [ ! -f keys/server_pub.txt ]; then
    echo ">>> Génération des clés RSA (une seule fois)..."
    $PY network/keygen.py
fi

start_server

step "1. Caesar (décalage de 5)"
run --algorithm caesar --key 5 --message "Bonjour Serveur"

step "2. Substitution (clé aléatoire)"
run --algorithm substitution --message "Bonjour Serveur"

step "3. Vigenère (clé LEMON)"
run --algorithm vigenere --key LEMON --message "Attack at dawn"

step "4. Playfair (grille 5x5)"
run --algorithm playfair --key "PLAYFAIR EXAMPLE" --message "hide the gold in the tree stump"

step "5. Hill (matrice 2x2)"
run --algorithm hill --key DDCF --message "HELP"

step "6. AES-128 en CBC"
run --algorithm aes --mode CBC --bits 128 --message "Bonjour Serveur"

step "7. AES-256 en CTR"
run --algorithm aes --mode CTR --bits 256 --message "Bonjour Serveur"

step "8. AES en ECB : 2 blocs identiques (32 fois A) donnent 2 chiffrés identiques"
run --algorithm aes --mode ECB --message "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

step "9. RSA + signature numérique"
run --algorithm rsa --message "Bonjour Serveur" --sign

step "10. Fausse signature (un pirate signe avec une autre clé)"
echo "\$ $PY examples/fake_client.py"
$PY examples/fake_client.py
sleep 1

step "11. Diffie-Hellman + AES (la clé n'est jamais envoyée)"
run --algorithm dh --bits 256 --mode CBC --message "Bonjour Serveur"

step "12. HMAC : le serveur est relancé avec un secret partagé"
start_server --secret monsecret
run --algorithm caesar --key 5 --message "Message authentique" --secret monsecret
run --algorithm caesar --key 5 --message "Message du pirate" --secret mauvaissecret

echo
echo "Fin de la démo."
