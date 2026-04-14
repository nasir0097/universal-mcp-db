"""seed_demo.py — creates demo.db with sample data for local testing"""
import sqlite3, os

db = os.path.join(os.path.dirname(__file__), "demo.db")
conn = sqlite3.connect(db)
cur = conn.cursor()

cur.executescript("""
CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT,
    country TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY,
    customer_id INTEGER REFERENCES customers(id),
    product TEXT,
    amount REAL,
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
""")

cur.executemany("INSERT OR IGNORE INTO customers (id,name,email,country) VALUES (?,?,?,?)", [
    (1, "Alice Johnson",  "alice@example.com",  "Canada"),
    (2, "Bob Smith",      "bob@example.com",    "USA"),
    (3, "Carol Williams", "carol@example.com",  "UK"),
    (4, "David Lee",      "david@example.com",  "Australia"),
])

cur.executemany("INSERT OR IGNORE INTO orders (id,customer_id,product,amount,status) VALUES (?,?,?,?,?)", [
    (1, 1, "Azure Plan",     299.99, "completed"),
    (2, 1, "Support Add-on",  49.99, "completed"),
    (3, 2, "AWS Starter",    199.99, "pending"),
    (4, 3, "Enterprise",     999.00, "completed"),
    (5, 4, "Azure Plan",     299.99, "cancelled"),
])

conn.commit()
conn.close()
print(f"Demo DB created at: {db}")
print("Tables: customers, orders")
