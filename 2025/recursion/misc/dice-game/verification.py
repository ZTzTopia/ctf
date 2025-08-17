import hashlib
import hmac

def sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()

def get_game_hash(game_seed, client_seed):
    return hmac.new(game_seed.encode(), client_seed.encode(), hashlib.sha256).hexdigest()

def get_number_from_hash(game_hash):
    return int(game_hash[:52 // 4], 16)

def get_roll(game_hash):
    seed = get_number_from_hash(game_hash)
    roll = abs((seed % 1000) + 1)
    return roll

client_seed = input("Enter Client Seed: ")
game_seed = input("Enter Game Seed: ")

keep_verifying = True
while keep_verifying:
    game_hash = get_game_hash(game_seed, client_seed)
    roll = get_roll(game_hash)

    game_seed = sha256(game_seed)

    print(f"Dice: {roll / 10}")
    print(f"Roll: {roll}")
    print(f"Previous Game Seed: {game_seed}")

    keep_verifying = input("Verify previous game? (y/n): ") == "y"
