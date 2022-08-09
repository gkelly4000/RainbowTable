import sys
import hashlib
##########################################################################
# Program to crack a SHA-1 hash using a generated rainbow table
# USAGE: python3 rainbowCrack.py [SHA-1 HASH TO CRACK] [NAME OF RAINBOW TABLE(without file extension)]
# For example: python3 rainbowCrack.py 7110eda4d09e062aa5e4a390b0a572ac0d2c0220 numeric2Len8
# Author: George Kelly
# Student Number: 18037010
############################################################################

# Function to map a SHA-1 hash to a integer within the size of the password space
# The hexidecimal hash to converted to a long integer
# The integer is then added together with a variable containing the current iteration
# Result is modulus divided by a prime number to ensure it falls within the password space
# A prime number is required to avoid collisions, meaning that two hashes should be unlikely
# To be reduced to the same integers
# Result is passed to intToPassword function to map the intger to a plaintext string
def reduce(hash, pos):
    hash = int(hash, 16)
    n = (hash + pos) % PRIME
    return intToPassword(n)

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

# Function to load a rainbow table from a text file
# Stored as a hash map to ensure constant lookup times (O(1))
def loadTable():
    table = {}
    with open(FILENAME) as file:
        for f in file:
            f = f.rstrip("\n")
            f = f.split(",")
            table[f[0]] = f[1]
    return table

# Function to rebuild a chain once a potential chain has been identified
# Takes starting string as input
# Hashes and reduces the starting string for the number of chain links
# Checking if a generated strings SHA-1 hash matches 
# The hash to crack passed in by the user
# Return plaintext if the hash matches
def crack(start):
    s = start
    for i in range(CHAINLEN):
        h = hashlib.sha1(s.encode()).hexdigest()
        if h == HASH:
            return s
        s = reduce(h, i)

def main():
    # Define global constants to store configuation parameters
    global HASH # The SHA-1 hash to crack
    global ALPHABET # The alphabet set
    global LEN # Length of alphabet set
    global PWLEN  # Max length of password
    global CHAINLEN # Number of links in a chain
    global CHAINNUM # Number of chains in a table
    global PRIME # Prime number to map integers into the password space
    global FILENAME # Filename of the table used to crack a password
    global CONFIG # Configuation filename for the table

    # Validating number of command line arguments
    # If incorrect number is passed in by the user
    # Input is taken from stdin
    if len(sys.argv) != 3:
        print("Incorrect number of command line arguments")
        print("Please enter the following:")

        HASH = input("Please enter hash to crack. ") # Hash to crack from stdin
        FILENAME = input("Please enter filename of table. ") # Filename of table from stdin
    else:
        HASH = sys.argv[1] # Hash to crack from command line argument
        FILENAME = sys.argv[2] # Table filename from command line argument

    CONFIG = FILENAME + "config" + ".txt" # Buil configuation filename string
    FILENAME = FILENAME + ".txt" # Build filename string

    # Open configuation file and store in array
    arr = []
    with open(CONFIG) as file:
        for f in file:
            f = f.rstrip("\n")
            arr.append(f)

    # Store configuation paraments in global constants
    ALPHABET = str(arr[0])
    LEN = len(ALPHABET)
    PWLEN = int(arr[1])
    CHAINLEN = int(arr[2])
    CHAINNUM = int(arr[3])
    PRIME = int(arr[4])

    table = loadTable() # load table from file
    # Search the table from the last position in a chain to the first
    for i in range(CHAINLEN-1, -1, -1):
        print("searching table... position: {}".format(i))
        h = HASH # Hash to crack

        # Loop from i to the last position in a chain
        # On first iteration: loops from CHAINLEN-1 to CHAINLEN
        # On second: CHAINLEN-2 to CHAINLEN
        # On third: CHAINLEN-3 TO CHAINLEN, etc.
        for j in range(i, CHAINLEN): 
            s = reduce(h, j) # Hash is reduced to plaintext string 
            h = hashlib.sha1(s.encode()).hexdigest() # Plaintext string is hashed
            if s in table: # If the plaintext string is a key in the table
                row = table.get(s) # Get corresponding value (starting string of chain) 
                pwd = crack(row) # Attempt to rebuild the chain, starting with the begining of the particular chain
                if pwd is not None: # If return value of crack is not None:
                    print("FOUND!") # Plaintext for the hash has been found
                    print(pwd) # Print plaintext password
                    sys.exit(0) # Exit with succesful return status
    print("not found") # If all positions have been searched and no plaintext has been found, the plaintext password hasn't been generated by the table
    sys.exit(0) # Exit with unsucessful return status                  

if __name__ == '__main__':
    main()