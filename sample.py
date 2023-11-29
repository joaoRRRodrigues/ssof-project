import requests


def get_user_details():
    user_id = input('id = ')  # entry point

    response = requests.get(f"https://api.example.com/user/{user_id}")

    return response.json()


def sensitive_operation():
    details = get_user_details()

    bank_balance = details['balance']  # sink

    if bank_balance > 1000:
        return 1
        # do something sensitive

def main():
    sensitive_operation()


if __name__ == '__main__':
    main()
