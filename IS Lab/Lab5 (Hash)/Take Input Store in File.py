def main():
    """Main function to take user input and store it in a file."""
    # Get the file name from the user
    file_name = input("Enter the name of the file to store input (e.g., 'input.txt'): ")

    print("Enter your input (type 'exit' to stop):")

    with open(file_name, 'a') as file:  # Open the file in append mode
        while True:
            user_input = input()  # Get input from the user
            if user_input.lower() == 'exit':  # Check for exit command
                print("Exiting the program.")
                break

            # Write the input to the file
            file.write(user_input + '\n')
            print(f"Stored: {user_input}")


if __name__ == "__main__":
    main()
