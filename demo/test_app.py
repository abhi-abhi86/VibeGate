import sqlite3
import tempfile
import os

from demo.app import app


def test_search_orders_returns_200():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, customer TEXT, total REAL)")
        conn.execute("INSERT INTO orders (customer, total) VALUES ('alice', 42.0)")
        conn.commit()
        conn.close()

        os.environ["DEMO_DB"] = path
        client = app.test_client()
        resp = client.get("/orders/search?customer=alice")
        assert resp.status_code == 200
        assert len(resp.get_json()["orders"]) == 1
    finally:
        os.environ.pop("DEMO_DB", None)
        if os.path.exists(path):
            os.remove(path)

