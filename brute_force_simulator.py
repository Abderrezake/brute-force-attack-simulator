from typing import Callable
from hashing import *
from brute_force import brute_force_attack
from colorama import Fore, init

init(autoreset=True)

# Dictionnaire des méthodes de hachage
HASH_METHODS = {
    "bcrypt": (hash_bcrypt, verify_bcrypt),
    "pbkdf2": (hash_pbkdf2, verify_pbkdf2),
    "sha256": (hash_sha256, lambda p, h: hash_sha256(p) == h),
    "md5": (hash_md5, lambda p, h: hash_md5(p) == h),
    "sha3": (hash_sha3, lambda p, h: hash_sha3(p) == h)
}

def get_valid_input(prompt: str, validation_func: Callable) -> str:
    """Valide les entrées utilisateur."""
    while True:
        user_input = input(Fore.CYAN + prompt).strip()
        if validation_func(user_input):
            return user_input
        print(Fore.RED + "Erreur : Entrée invalide.\n")

def main():
    # Choix de la méthode
    method = get_valid_input(
        f"Méthode ({'/'.join(HASH_METHODS.keys())}): ",
        lambda x: x.lower() in HASH_METHODS
    ).lower()

    password = get_valid_input("Mot de passe: ", lambda x: len(x) > 0)
    max_length = int(get_valid_input("Longueur max (1-6): ", lambda x: x.isdigit() and 1 <= int(x) <= 6))

    # Hachage du mot de passe
    hash_func, verify_func = HASH_METHODS[method]
    hashed = hash_func(password)

    # Lancement de l'attaque
    result = brute_force_attack(
        target_hash=hashed,
        max_length=max_length,
        hash_func=lambda x: hash_func(x) if method in ["bcrypt", "pbkdf2"] else hash_func(x)
    )

    # Affichage des résultats
    if result[0]:
        print(f"\n{Fore.GREEN}[SUCCÈS] Mot de passe trouvé : {Fore.YELLOW}{result[0]}")
        print(f"{Fore.CYAN}Temps : {result[1]:.2f}s | Tentatives : {result[2]} | Taux : {result[3]:.2f} tentatives/s")
    else:
        print(f"\n{Fore.RED}[ÉCHEC] Mot de passe non trouvé.")

if __name__ == "__main__":
    main()