import hashlib
import time
import random
import string


# Function to generate a random string of specified length
def generate_random_string(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


# Function to hash data using different algorithms
def hash_data(data, algorithm):
    hasher = hashlib.new(algorithm)
    hasher.update(data.encode())
    return hasher.hexdigest()


# Function to measure hashing performance and detect collisions
def analyze_hashing_performance(num_strings):
    # Generate a dataset of random strings
    dataset = [generate_random_string(random.randint(10, 20)) for _ in range(num_strings)]

    # Define hash algorithms to test
    algorithms = ['md5', 'sha1', 'sha256']

    results = {}

    for algorithm in algorithms:
        print(f"\nAnalyzing {algorithm.upper()}...")

        # Measure time taken to compute hashes
        start_time = time.time()
        hashes = [hash_data(data, algorithm) for data in dataset]
        end_time = time.time()

        computation_time = end_time - start_time
        results[algorithm] = {'time': computation_time, 'hashes': hashes}

        # Check for collisions
        hash_set = set()
        collisions = 0

        for hash_value in hashes:
            if hash_value in hash_set:
                collisions += 1
            hash_set.add(hash_value)

        results[algorithm]['collisions'] = collisions

    return results


# Main function to run the experiment
def main():
    # Take user input for the number of strings
    while True:
        try:
            num_strings = int(input("Enter the number of random strings to generate (between 50 and 100): "))
            if 50 <= num_strings <= 100:
                break
            else:
                print("Please enter a number between 50 and 100.")
        except ValueError:
            print("Invalid input. Please enter an integer.")

    print(f"\nGenerating dataset of {num_strings} random strings...")

    # Analyze performance of different hash algorithms
    results = analyze_hashing_performance(num_strings)

    # Display the results
    for algorithm, result in results.items():
        print(f"\n{algorithm.upper()} Results:")
        print(f"Time taken: {result['time']:.6f} seconds")
        print(f"Number of collisions: {result['collisions']}")

    print("\nExperiment completed.")


if __name__ == "__main__":
    main()
