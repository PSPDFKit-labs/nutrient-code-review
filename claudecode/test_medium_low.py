"""Test file with medium/low severity issues only (no HIGH severity)."""


def find_duplicates(items):
    """Find duplicate items in a list.

    Medium severity: O(n²) algorithm when O(n) with set is possible.
    """
    duplicates = []
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            if items[i] == items[j] and items[i] not in duplicates:
                duplicates.append(items[i])
    return duplicates


def calculate_discount(price, discount_percent):
    """Calculate discounted price.

    Low severity: Uses magic number instead of named constant.
    """
    if discount_percent > 50:  # Magic number - what does 50 represent?
        discount_percent = 50
    return price * (1 - discount_percent / 100)


def process_data(data):
    """Process data and return result.

    Low severity: Doesn't handle empty input gracefully.
    """
    total = 0
    for item in data:
        total += item["value"]  # Will crash if data is empty or item has no "value"
    return total / len(data)  # Division by zero if data is empty


def format_user_info(user):
    """Format user information for display.

    Low severity: Unused variable.
    """
    unused_temp = user.get("temp", "default")  # Never used
    name = user.get("name", "Unknown")
    email = user.get("email", "N/A")
    return f"{name} <{email}>"
