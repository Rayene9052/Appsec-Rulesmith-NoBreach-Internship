"""
In-memory data store for the secure demo API — identical seed data to
apps/vulnerable-api/data_store.py so the same DAST rules and test
accounts work unmodified against both targets, letting the remediation
validator do a fair before/after comparison.
"""

USERS = {
    1: {
        "id": 1,
        "username": "alice",
        "password": "alice123",
        "role": "user",
        "email": "alice@example.com",
    },
    2: {
        "id": 2,
        "username": "bob",
        "password": "bob123",
        "role": "user",
        "email": "bob@example.com",
    },
    3: {
        "id": 3,
        "username": "admin",
        "password": "admin123",
        "role": "admin",
        "email": "admin@nobreach.local",
    },
}

ORDERS = {
    101: {"id": 101, "user_id": 1, "item": "Laptop", "total": 1200},
    102: {"id": 102, "user_id": 2, "item": "Keyboard", "total": 80},
}


def find_user(user_id):
    return USERS.get(user_id)


def find_user_by_username(username):
    for user in USERS.values():
        if user["username"] == username:
            return user
    return None


def find_order(order_id):
    return ORDERS.get(order_id)
