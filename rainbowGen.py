import secrets
import random
import hashlib
import sys
#####################################################################
# Program to generate rainbow table to crack SHA-1 hashes
# Input it taken either through command line arguments or from stdin
# USAGE: python3 rainbowGen.py [ALPHABET SET] [MAX PASSWORD LENGTH] [CHAIN LENGTH] [CHAIN NUMBER] [PRIME NUMBER] [FILENAME TO SAVE TABLE AS]
# For example: python3 rainbowGen.py 0123456789 8 5000 40000 111111113 numericLen8
# Saves table to a text file and also creates a configuartion file 
# In the format: ALPHABET, MAX PASSWORD LENGTH, CHAIN LENGTH, CHAIN NUMBER
# To save the user having to reinput those parameters when using 
# The table to crack a password
# Author: George Kelly
# Student Number: 18037010
#####################################################################

# Function to calculate total password space 
def calculatePassSpace():
    len = PWLEN
    sum = 0
    while len >= 0:
        sum += LEN**len
        len -= 1
    return sum

# Function to map an integer to a string password from a given alphabet set
# Function takes an intger and converts to base n
# Where n is the length of the alphabet set
# Each digit in the base n number is used to index into a charcter array 
# And generate a password string
def intToPassword(n):
    rem = 0
    arr = []
    while n >= 0:
        rem = int(n % LEN)
        n = int(n / LEN)
        arr.append(ALPHABET[rem])
        n -= 1
    s = ''.join(map(str, arr))
    return s

# Function to generate a random password of random length from a given alphabet set
# Secrets module is used to randomly chose each individual character
# Random module is used to randomly determine the length of the generated string
# Secrets used rather than random for the choice of characters as the module
# Is more cyptographically secure, meaning it's less deterministic than pythons random module
# As the module does not rely on software state and number sequences are not reproducable
# Modifying the seed of secrets module has no effect, making it a more secure PRNG for cryptographic purposes
def genString():
    s = ''.join(secrets.choice(ALPHABET) for i in range(random.randint(1, PWLEN)))
    return s 

# Function to map a SHA-1 hash to a integer within the size of the password space
# The hexidecimal hash to converted to a long integer
# The integer is then added together with a variable containing the current iteration
# Result is modulus divided by a prime number to ensure it falls within the password space
# A prime number is required to avoid collisions, meaning that two hashes should be unlikely
# To be reduced to the same integers
def reduce(hash, pos):
    hash = int(hash, 16)
    n = (hash + pos) % PRIME
    return intToPassword(n)

# Function to generate a chain for the rainbow table
# A starting string is passed in as input
# The string is then hashed and reduced for the number of 
# Chain links determined by the useer
# The final string is returned
def genChain(start):
    s = start
    for i in range(CHAINLEN -1):
        h = hashlib.sha1(s.encode())
        s = reduce(h.hexdigest(), i)
    return s

# Function to generate the rainbow table
# The table is stored as hash map to ensure constant lookup times (O(1))
def genTable():
    table = {}
    while len(table) < CHAINNUM: # Loop while the size of the table is less than the user defined
        print("Generating table: current length = {}".format(len(table)))
        start = genString() # Generate starting string
        s = genChain(start) # Generate last password in the chains

        # If last string of a chain isn't already in the table
        # Store last string as key, and startin string as value
        # If key already exists in the table,
        # Discard entire chain and regenerate with different random starting string
        if s not in table: 
            table[s] = start
    return table # Return generated table when appropriate size is reached
    
def main():
    # Declare global constants to store configuration parameters
    global ALPHABET # Alphabet set to generate passwords from
    global LEN # Length of alphabet set
    global PWLEN # Max length of passwords
    global CHAINLEN # Length of chain
    global CHAINNUM # Number of chains
    global PRIME # Prime number to map integers into password space
    global FILENAME # Name of file to save the generated table as
    global CONFIG # Configuation file name, used to store alhphabet set, password length, number and length of chains for a generated table

    # Validate number of command line arguments
    # If incorrect number of command line arguments are passed
    # Then the user input is taken fron stdin
    if len(sys.argv) != 7:
        print("Incorrect number of command line arguments.")
        print("USAGE: python3 rainbowGen.py [ALPHABET SET] [MAX PASSWORD LENGTH] [CHAIN LENGTH] [CHAIN NUMBER] [PRIME NUMBER] [TABLE NAME TO SAVE AS] ")
        print("Please enter configuration parameters: ")

        ALPHABET = input("Please enter the alphabet set: ")
        LEN = len(ALPHABET)
        
        # Infinite loop as python lacks do while loops
        # The first line has to be executed once
        # If input passes validation, break out of the loop
        while True:
            PWLEN = input("Please enter max password length: ")
            if PWLEN.isdigit():
                PWLEN = int(PWLEN)
                break
            else:
                print("Error: password length must be numeric. ")

        # Infinite loop as python lacks do while loops
        # The first line has to be executed once
        # If input passes validation, break out of the loop
        while True:
            CHAINLEN = input("Please enter the length of chains. ")
            if CHAINLEN.isdigit():
                CHAINLEN = int(CHAINLEN)
                break
            else:
                print("Error: Chain length must be numeric. ")
        
        # Calculate total password space and given recomended table size parameters 
        # Bases upon size of password space and length of chains
        size = calculatePassSpace() 
        print("Size of password space is: {}".format(size))
        print("Recomended table size with chain length: {} is:".format(CHAINLEN))
        print("chain number: {}".format(int((size * 1.8) / CHAINLEN))) # 1.8 is used to ensure good coverage of the password space

        # Infinite loop as python lacks do while loops
        # The first line has to be executed once
        # If input passes validation, break out of the loop
        while True:
            CHAINNUM = input("Please enter the number of chains. ")
            if CHAINNUM.isdigit():
                CHAINNUM = int(CHAINNUM)
                break
            else:
                print("Error: Number of chains must be numeric. ")

        # Infinite loop as python lacks do while loops
        # The first line has to be executed once
        # If input passes validation, break out of the loop
        while True:
            PRIME = input("Please enter a prime number: (Prime greater than password space recomended ({})). ".format(size))
            if PRIME.isdigit():
                PRIME = int(PRIME)
                break
            else:
                print("Error: Prime must be numeric. ")
                
        FILENAME = input("Please enter the file name for the generated table. ")
    else:
        # If correct number of command line arguments are passed, 
        # Store them in global constant variables
        ALPHABET = str(sys.argv[1])
        LEN = len(ALPHABET)

        # Validating command line arguments
        PWLEN = sys.argv[2]
        if PWLEN.isdigit():
            PWLEN = int(PWLEN)
        else:
            print("Command line argument error: Password length must be an integer. ")
            sys.exit(1) # Exit with error status

        CHAINLEN = sys.argv[3]
        if CHAINLEN.isdigit():
            CHAINLEN = int(CHAINLEN)
        else:
            print("Command line argument error: Chain length must be an integer. ")
            sys.exit(1) # Exit with error status


        CHAINNUM = sys.argv[4]
        if CHAINNUM.isdigit():
            CHAINNUM = int(CHAINNUM)
        else:
            print("Command line argument error: Chain length must be an integer. ")
            sys.exit(1) # Exit with error status

        PRIME =  sys.argv[5]
        if PRIME.isdigit():
            PRIME = int(PRIME)
        else:
            print("Command line argument error: Prime number must be an integer. ")
            sys.exit(1) # Exit with error status

        FILENAME = str(sys.argv[6]) # Ensures filename is taken as a string even if the name is all numeric


    CONFIG = FILENAME + "config" + ".txt" # Buidling config filename string
    FILENAME = FILENAME + ".txt" # Building filename string

    # Write configuation parameters to text file for more user friendly cracking using the generated tables
    with open (CONFIG, 'w') as file:
        file.write("{}\n{}\n{}\n{}\n{}\n".format(ALPHABET, PWLEN, CHAINLEN, CHAINNUM, PRIME))

    table = genTable() # Generate the table
    print("Rainbow table generated")

    # Write table to text file
    with open(FILENAME, "w") as file:
        for t in table:
            file.write("{},{}\n".format(t, table.get(t)))
    print("Table saved to disk, filename: {}, configuration filename: {}".format(FILENAME, CONFIG))
    sys.exit(0) # Exit with sucessful return status

if __name__ == '__main__':
    main()
