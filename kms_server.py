#!/usr/bin/env python3

# =============================================================================
#
# Quantum Key Management System (QKMS)
#
# Main Entry Point
#
# =============================================================================

from protocol_manager import execute_protocol


def menu():

    print()
    print("=" * 70)
    print("Distributed Quantum Key Management System")
    print("=" * 70)

    print()
    print("1. BB84 Protocol")
    print("2. E92 Protocol")
    print("3. CVQKD")
    print("4. Exit")
    print()


def main():

    while True:

        menu()

        choice = input("Select Protocol : ").strip()

        if choice == "1":

            execute_protocol("BB84")

        elif choice == "2":

            execute_protocol("E92")

        elif choice == "3":

            execute_protocol("CVQKD")

        elif choice == "4":

            print("\nGood Bye\n")
            break

        else:

            print("\nInvalid Selection\n")


if __name__ == "__main__":

    main()
