import argparse
import os
import random
import hashlib


# Construct the argument parser
ap = argparse.ArgumentParser() 
ap.add_argument("-s", "--string", required=True, help="Input string to be split")
ap.add_argument("-r", "--rno", required=True, help="Reference number")

# Parse the arguments
args = vars(ap.parse_args())
input_data = args["string"]
n = int(args["rno"])

# Function to split and save the string
def split_and_save(data,n):
    """
    Splits the input string into 5 parts and saves each part as a hash block file
    in the same directory where the script is running.
    
    Args:
        data (str): The input string to be split and saved.
    """
    # Validate input data
    if not isinstance(data, str):
        raise ValueError("Input data must be a string.")

    # Calculate the length of each split
    split_size = len(data) // 5
    remainder = len(data) % 5  # Handle any leftover characters

    # Split the data into 5 parts
    parts = [data[i * split_size:(i + 1) * split_size] for i in range(5)]

    # Distribute the remainder characters (if any) among the parts
    for i in range(remainder):
        parts[i] += data[-remainder + i]
        

    if not os.path.exists("blocks"):
        os.makedirs("blocks")

    # Generate a random number for file naming 

    # Save each part to a separate hash block file
    for i, part in enumerate(parts, 1):
        output_filename = f"blocks/hashblock{i}_{n}.hbl"
        with open(output_filename, "w") as outfile:
            outfile.write(compute_hash(part))

    print(f"Data has been split into 5 parts and saved as hashblock files.")

def compute_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()


# Call the function with the parsed string
split_and_save(input_data,n)
