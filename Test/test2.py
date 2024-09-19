# Function to convert a base-9 number to decimal
def base9_to_decimal(base9_number):
    # Convert the number (string format) from base-9 to decimal (base-10)
    decimal_number = 0
    base = 9
    
    # Process each digit and calculate its decimal value
    for i, digit in enumerate(reversed(str(base9_number))):
        decimal_number += int(digit) * (base ** i)
    
    return decimal_number

# Test the function with the 9-based number '114514'
base9_number = 114514
decimal_value = base9_to_decimal(base9_number)
print(decimal_value)
