import hashlib

def hash_file(file_path, num_iterations):
    with open(file_path, "rb") as file:
        data = file.read()
        for _ in range(num_iterations):
            hash_object = hashlib.sha256()
            hash_object.update(data)
            data = hash_object.digest()
    return data.hex()

if __name__ == "__main__":
    file_path = input("Entrez le chemin du fichier à hasher : ")
    num_iterations = int(input("Entrez le nombre d'itérations de hashage : "))

    hashed_data = hash_file(file_path, num_iterations)
    print("Résultat du hash :", hashed_data)
