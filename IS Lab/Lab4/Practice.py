import os
import time


def person1():
    # Get input from the terminal
    data = input("Person 1, enter your message: ")

    # Write the data to the file
    with open('shared_file.txt', 'w') as f:
        f.write(data + '\n')
    print("Person 1 has written to the file.")


def person2():
    # Wait for Person 1 to finish writing
    while not os.path.exists('shared_file.txt'):
        print("Waiting for Person 1 to write...")
        time.sleep(1)  # Check every second

    # Read the content written by Person 1
    with open('shared_file.txt', 'r') as f:
        content = f.read()
    print("Person 2 reads from the file:\n", content)

    # Get additional input from the terminal
    extra_data = input("Person 2, enter your extra message: ")

    # Write the extra data to the file
    with open('shared_file.txt', 'a') as f:
        f.write(extra_data + '\n')
    print("Person 2 has written to the file.")


def person3():
    # Wait for Person 2 to finish writing
    while not os.path.exists('shared_file.txt'):
        print("Waiting for Person 2 to write...")
        time.sleep(1)  # Check every second

    # Read the content written by Person 2
    with open('shared_file.txt', 'r') as f:
        content = f.read()
    print("Person 3 reads from the file:\n", content)

    # Get additional input from the terminal
    more_data = input("Person 3, enter your additional message: ")

    # Write the additional data to the file
    with open('shared_file.txt', 'a') as f:
        f.write(more_data + '\n')
    print("Person 3 has written to the file.")


if __name__ == '__main__':
    person1()  # Start with Person 1
    person2()  # Then Person 2
    person3()  # Finally Person 3
