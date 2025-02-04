import time
from typing import Callable, Union
from tqdm import tqdm

def brute_force_attack(
    target_hash: Union[str, bytes],
    max_length: int,
    hash_func: Callable[[str], Union[str, bytes]],
    charset: str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
) -> tuple:
    """Attaque générique avec support de toutes les méthodes de hachage."""
    start_time = time.time()
    attempts = 0
    stack = [""]
    cracked = None

    # Calcul du nombre total de combinaisons
    total = sum(len(charset)**i for i in range(1, max_length + 1))

    with tqdm(total=total, desc="Attaque en cours", unit="tentative") as pbar:
        while stack and not cracked:
            current = stack.pop()
            if len(current) >= max_length:
                continue
            for char in charset:
                test = current + char
                attempts += 1
                pbar.update(1)
                if hash_func(test) == target_hash:
                    cracked = test
                    stack.clear()
                    break
                stack.append(test)

    duration = time.time() - start_time
    return cracked, duration, attempts, attempts / duration if duration > 0 else 0