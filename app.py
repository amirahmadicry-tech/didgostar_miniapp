import os, json, hmac, hashlib, sqlite3, time, re
from urllib.parse import parse_qsl
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN", "")

def normalize_digits(value):
    """Convert Persian/Arabic digits to English digits and trim whitespace."""
    translation = str.maketrans(
        "۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩",
        "01234567890123456789"
    )
    return str(value or "").translate(translation).strip()

def parse_admin_ids(value):
    """Read admin Telegram IDs separated by commas, semicolons, spaces or newlines."""
    normalized = normalize_digits(value)
    return {
        item.strip()
        for item in re.split(r"[,;\s]+", normalized)
        if item.strip()
    }

ADMIN_IDS = parse_admin_ids(os.getenv("ADMIN_TELEGRAM_IDS", ""))
ALLOW_PREVIEW = os.getenv("ALLOW_BROWSER_PREVIEW", "false").lower() == "true"
DB = Path(__file__).with_name("didgostar.db")

app = FastAPI(title="Didgostar Mini App API")
app.mount("/static", StaticFiles(directory="static"), name="static")


def is_admin_telegram_id(telegram_id):
    return normalize_digits(telegram_id) in ADMIN_IDS


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


def columns(con, table):
    return {r["name"] for r in con.execute(f"PRAGMA table_info({table})").fetchall()}


def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users (
            telegram_id TEXT PRIMARY KEY, first_name TEXT, username TEXT,
            is_partner INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
            active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
            category TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
            retail_price INTEGER NOT NULL, partner_price INTEGER NOT NULL,
            stock INTEGER NOT NULL DEFAULT 0, image_url TEXT NOT NULL DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1)""")
        con.execute("""CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT, telegram_id TEXT NOT NULL,
            customer_name TEXT NOT NULL, phone TEXT NOT NULL, address TEXT NOT NULL,
            items_json TEXT NOT NULL, total INTEGER NOT NULL, status TEXT NOT NULL,
            created_at INTEGER NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS discounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL, amount INTEGER NOT NULL, min_total INTEGER NOT NULL DEFAULT 0,
            max_uses INTEGER NOT NULL DEFAULT 0, used_count INTEGER NOT NULL DEFAULT 0,
            starts_at INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1)""")

        # Safe additive migration for existing databases
        if "discount_code" not in columns(con, "orders"):
            con.execute("ALTER TABLE orders ADD COLUMN discount_code TEXT NOT NULL DEFAULT ''")
        if "discount_amount" not in columns(con, "orders"):
            con.execute("ALTER TABLE orders ADD COLUMN discount_amount INTEGER NOT NULL DEFAULT 0")

        count = con.execute("SELECT COUNT(*) FROM categories").fetchone()[0]
        if count == 0:
            names = ["دوربین مداربسته", "DVR و NVR", "دزدگیر اماکن", "تجهیزات شبکه"]
            con.executemany(
                "INSERT OR IGNORE INTO categories(name,created_at) VALUES(?,?)",
                [(n, int(time.time())) for n in names]
            )

        count = con.execute("SELECT COUNT(*) FROM products").fetchone()[0]
        if count == 0:
            demo = [
                ("دوربین بولت ۲ مگاپیکسل", "دوربین مداربسته", "مشخصات نمونه؛ پیش از فروش ویرایش شود.", 3500000, 3100000, 20, ""),
                ("دوربین دام ۴ مگاپیکسل", "دوربین مداربسته", "مشخصات نمونه؛ پیش از فروش ویرایش شود.", 5200000, 4700000, 12, ""),
                ("دستگاه ضبط ۸ کانال", "DVR و NVR", "مدل و قابلیت‌ها را دقیق درج کنید.", 8900000, 8200000, 8, ""),
                ("دزدگیر اماکن", "دزدگیر اماکن", "اقلام داخل جعبه را دقیق درج کنید.", 7800000, 7100000, 10, ""),
                ("سوئیچ شبکه ۸ پورت", "تجهیزات شبکه", "نوع مدیریتی یا غیرمدیریتی را مشخص کنید.", 2400000, 2150000, 15, "")
            ]
            con.executemany("""INSERT INTO products
                (title,category,description,retail_price,partner_price,stock,image_url)
                VALUES (?,?,?,?,?,?,?)""", demo)


init_db()


def verify_init_data(init_data: str):
    if not BOT_TOKEN:
        if ALLOW_PREVIEW:
            return {"id": "preview-user", "first_name": "کاربر آزمایشی", "username": "preview"}
        raise HTTPException(503, "Telegram bot is not configured")

    if not init_data:
        raise HTTPException(401, "Telegram initData is required")

    data = dict(parse_qsl(init_data, keep_blank_values=True))
    received_hash = data.pop("hash", None)
    if not received_hash:
        raise HTTPException(401, "Invalid Telegram data")

    check = "\n".join(f"{k}={v}" for k, v in sorted(data.items()))
    secret = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    calculated = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(calculated, received_hash):
        raise HTTPException(401, "Telegram data verification failed")

    try:
        auth_date = int(data.get("auth_date", "0"))
    except (TypeError, ValueError):
        raise HTTPException(401, "Invalid Telegram authentication date")

    if time.time() - auth_date > 86400:
        raise HTTPException(401, "Telegram session expired")

    try:
        user = json.loads(data.get("user", "{}"))
    except (TypeError, ValueError):
        raise HTTPException(401, "Invalid Telegram user data")

    if not user.get("id"):
        raise HTTPException(401, "Telegram user missing")

    return user


def current_user(authorization: Optional[str]):
    raw = (authorization or "").removeprefix("tma ").strip()
    user = verify_init_data(raw)
    tid = normalize_digits(user["id"])

    with db() as con:
        con.execute(
            """INSERT OR IGNORE INTO users(telegram_id,first_name,username,created_at)
               VALUES(?,?,?,?)""",
            (tid, user.get("first_name", ""), user.get("username", ""), int(time.time()))
        )
        con.execute(
            "UPDATE users SET first_name=?, username=? WHERE telegram_id=?",
            (user.get("first_name", ""), user.get("username", ""), tid)
        )
        row = con.execute("SELECT * FROM users WHERE telegram_id=?", (tid,)).fetchone()

    return user, row


def require_admin(authorization):
    user, _ = current_user(authorization)
    if not is_admin_telegram_id(user["id"]):
        raise HTTPException(403, "دسترسی مدیر ندارید")
    return user


class ProductIn(BaseModel):
    title: str = Field(min_length=2, max_length=160)
    category: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=2000)
    retail_price: int = Field(ge=0)
    partner_price: int = Field(ge=0)
    stock: int = Field(default=0, ge=0)
    image_url: str = Field(default="", max_length=1000)
    active: bool = True


class CategoryIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)


class DiscountIn(BaseModel):
    code: str = Field(min_length=3, max_length=32)
    kind: str
    amount: int = Field(gt=0)
    min_total: int = Field(default=0, ge=0)
    max_uses: int = Field(default=0, ge=0)
    expires_at: int = 0
    active: bool = True


class OrderIn(BaseModel):
    customer_name: str = Field(min_length=2, max_length=100)
    phone: str = Field(min_length=6, max_length=30)
    address: str = Field(min_length=5, max_length=500)
    items: list[dict]
    discount_code: str = ""


@app.get("/", response_class=HTMLResponse)
def home():
    return Path("static/index.html").read_text(encoding="utf-8")


@app.get("/api/me")
def me(authorization: Optional[str] = Header(default=None)):
    user, row = current_user(authorization)
    telegram_id = normalize_digits(user["id"])
    return {
        "telegram_id": telegram_id,
        "first_name": user.get("first_name", ""),
        "username": user.get("username", ""),
        "is_partner": bool(row["is_partner"]),
        "is_admin": is_admin_telegram_id(telegram_id)
    }


@app.get("/api/categories")
def categories(authorization: Optional[str] = Header(default=None)):
    current_user(authorization)
    with db() as con:
        rows = con.execute("SELECT name FROM categories WHERE active=1 ORDER BY name").fetchall()
    return ["همه"] + [r["name"] for r in rows]


@app.get("/api/products")
def products(authorization: Optional[str] = Header(default=None)):
    _, row = current_user(authorization)
    with db() as con:
        rows = con.execute("SELECT * FROM products WHERE active=1 ORDER BY id DESC").fetchall()

    partner = bool(row["is_partner"])
    return [
        {
            "id": p["id"],
            "title": p["title"],
            "category": p["category"],
            "description": p["description"],
            "price": p["partner_price"] if partner else p["retail_price"],
            "retail_price": p["retail_price"] if partner else None,
            "stock": p["stock"],
            "image_url": p["image_url"]
        }
        for p in rows
    ]


@app.post("/api/orders")
def create_order(order: OrderIn, authorization: Optional[str] = Header(default=None)):
    user, row = current_user(authorization)
    if not order.items:
        raise HTTPException(400, "سبد خرید خالی است")

    partner = bool(row["is_partner"])
    clean = []
    total = 0

    with db() as con:
        for item in order.items:
            try:
                pid, qty = int(item["product_id"]), int(item["quantity"])
            except Exception:
                raise HTTPException(400, "قلم سفارش نامعتبر است")

            p = con.execute("SELECT * FROM products WHERE id=? AND active=1", (pid,)).fetchone()
            if qty < 1 or qty > 100 or not p or p["stock"] < qty:
                raise HTTPException(400, "محصول ناموجود یا موجودی ناکافی است")

            price = p["partner_price"] if partner else p["retail_price"]
            total += price * qty
            clean.append({
                "product_id": pid,
                "title": p["title"],
                "quantity": qty,
                "unit_price": price
            })

        code = (order.discount_code or "").strip().upper()
        off = 0

        if code:
            d = con.execute(
                "SELECT * FROM discounts WHERE code=? AND active=1", (code,)
            ).fetchone()
            now = int(time.time())

            if (
                not d
                or (d["starts_at"] and now < d["starts_at"])
                or (d["expires_at"] and now > d["expires_at"])
                or (d["max_uses"] and d["used_count"] >= d["max_uses"])
                or total < d["min_total"]
            ):
                raise HTTPException(400, "کد تخفیف معتبر نیست یا شرایط استفاده را ندارد")

            off = min(
                total,
                int(total * d["amount"] / 100) if d["kind"] == "percent" else d["amount"]
            )
            con.execute(
                "UPDATE discounts SET used_count=used_count+1 WHERE id=?",
                (d["id"],)
            )

        final = total - off
        cur = con.execute(
            """INSERT INTO orders
               (telegram_id,customer_name,phone,address,items_json,total,status,created_at,discount_code,discount_amount)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (
                normalize_digits(user["id"]),
                order.customer_name,
                order.phone,
                order.address,
                json.dumps(clean, ensure_ascii=False),
                final,
                "pending",
                int(time.time()),
                code,
                off
            )
        )

    return {
        "ok": True,
        "order_id": cur.lastrowid,
        "total": final,
        "subtotal": total,
        "discount": off,
        "status": "pending"
    }


# Admin APIs
@app.get("/api/admin/summary")
def admin_summary(authorization: Optional[str] = Header(default=None)):
    require_admin(authorization)
    with db() as con:
        return {
            "customers": con.execute("SELECT COUNT(*) FROM users").fetchone()[0],
            "products": con.execute("SELECT COUNT(*) FROM products").fetchone()[0],
            "orders": con.execute("SELECT COUNT(*) FROM orders").fetchone()[0],
            "pending": con.execute("SELECT COUNT(*) FROM orders WHERE status='pending'").fetchone()[0],
            "revenue": con.execute(
                "SELECT COALESCE(SUM(total),0) FROM orders WHERE status IN ('paid','completed')"
            ).fetchone()[0]
        }


@app.get("/api/admin/customers")
def admin_customers(authorization: Optional[str] = Header(default=None)):
    require_admin(authorization)
    with db() as con:
        return [
            dict(r) for r in con.execute(
                """SELECT u.*,COUNT(o.id) order_count,
                   COALESCE(SUM(o.total),0) total_spent,MAX(o.created_at) last_order
                   FROM users u LEFT JOIN orders o ON o.telegram_id=u.telegram_id
                   GROUP BY u.telegram_id ORDER BY u.created_at DESC LIMIT 1000"""
            ).fetchall()
        ]


@app.get("/api/admin/customers/{tid}")
def admin_customer(tid: str, authorization: Optional[str] = Header(default=None)):
    require_admin(authorization)
    with db() as con:
        u = con.execute("SELECT * FROM users WHERE telegram_id=?", (tid,)).fetchone()
        if not u:
            raise HTTPException(404, "مشتری پیدا نشد")
        orders = con.execute(
            "SELECT * FROM orders WHERE telegram_id=? ORDER BY id DESC", (tid,)
        ).fetchall()
    return {"customer": dict(u), "orders": [dict(x) for x in orders]}


@app.delete("/api/admin/customers/{tid}")
def delete_customer(tid: str, authorization: Optional[str] = Header(default=None)):
    require_admin(authorization)
    if is_admin_telegram_id(tid):
        raise HTTPException(400, "حذف حساب مدیر مجاز نیست")
    with db() as con:
        cur = con.execute("DELETE FROM users WHERE telegram_id=?", (normalize_digits(tid),))
    if not cur.rowcount:
        raise HTTPException(404, "مشتری پیدا نشد")
    return {"ok": True}


@app.post("/api/admin/customers/{tid}/partner")
def set_partner(tid: str, body: dict, authorization: Optional[str] = Header(default=None)):
    require_admin(authorization)
    with db() as con:
        cur = con.execute(
            "UPDATE users SET is_partner=? WHERE telegram_id=?",
            (1 if body.get("enabled") else 0, normalize_digits(tid))
        )
    if not cur.rowcount:
        raise HTTPException(404, "مشتری پیدا نشد")
    return {"ok": True}


@app.get("/api/admin/categories")
def admin_categories(authorization: Optional[str] = Header(default=None)):
    require_admin(authorization)
    with db() as con:
        return [dict(r) for r in con.execute("SELECT * FROM categories ORDER BY id DESC").fetchall()]


@app.post("/api/admin/categories")
def add_category(body: CategoryIn, authorization: Optional[str] = Header(default=None)):
    require_admin(authorization)
    try:
        with db() as con:
            cur = con.execute(
                "INSERT INTO categories(name,created_at) VALUES(?,?)",
                (body.name.strip(), int(time.time()))
            )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "این دسته‌بندی قبلاً ثبت شده است")
    return {"ok": True, "id": cur.lastrowid}


@app.patch("/api/admin/categories/{cid}")
def edit_category(cid: int, body: CategoryIn, authorization: Optional[str] = Header(default=None)):
    require_admin(authorization)
    with db() as con:
        old = con.execute("SELECT name FROM categories WHERE id=?", (cid,)).fetchone()
        if not old:
            raise HTTPException(404, "دسته‌بندی پیدا نشد")
        try:
            con.execute(
                "UPDATE categories SET name=? WHERE id=?",
                (body.name.strip(), cid)
            )
            con.execute(
                "UPDATE products SET category=? WHERE category=?",
                (body.name.strip(), old["name"])
            )
        except sqlite3.IntegrityError:
            raise HTTPException(409, "نام دسته‌بندی تکراری است")
    return {"ok": True}


@app.delete("/api/admin/categories/{cid}")
def delete_category(cid: int, authorization: Optional[str] = Header(default=None)):
    require_admin(authorization)
    with db() as con:
        row = con.execute("SELECT name FROM categories WHERE id=?", (cid,)).fetchone()
        if not row:
            raise HTTPException(404, "دسته‌بندی پیدا نشد")
        used = con.execute(
            "SELECT COUNT(*) FROM products WHERE category=?", (row["name"],)
        ).fetchone()[0]
        if used:
            raise HTTPException(409, "ابتدا محصولات این دسته را به دسته دیگری منتقل کنید")
        con.execute("DELETE FROM categories WHERE id=?", (cid,))
    return {"ok": True}


@app.get("/api/admin/products")
def admin_products(authorization: Optional[str] = Header(default=None)):
    require_admin(authorization)
    with db() as con:
        return [dict(r) for r in con.execute("SELECT * FROM products ORDER BY id DESC").fetchall()]


@app.post("/api/admin/products")
def add_product(p: ProductIn, authorization: Optional[str] = Header(default=None)):
    require_admin(authorization)
    with db() as con:
        cur = con.execute(
            """INSERT INTO products
               (title,category,description,retail_price,partner_price,stock,image_url,active)
               VALUES(?,?,?,?,?,?,?,?)""",
            (p.title, p.category, p.description, p.retail_price, p.partner_price,
             p.stock, p.image_url, int(p.active))
        )
    return {"ok": True, "product_id": cur.lastrowid}


@app.put("/api/admin/products/{pid}")
def update_product(pid: int, p: ProductIn, authorization: Optional[str] = Header(default=None)):
    require_admin(authorization)
    with db() as con:
        cur = con.execute(
            """UPDATE products SET title=?,category=?,description=?,retail_price=?,
               partner_price=?,stock=?,image_url=?,active=? WHERE id=?""",
            (p.title, p.category, p.description, p.retail_price, p.partner_price,
             p.stock, p.image_url, int(p.active), pid)
        )
    if not cur.rowcount:
        raise HTTPException(404, "محصول پیدا نشد")
    return {"ok": True}


@app.delete("/api/admin/products/{pid}")
def delete_product(pid: int, authorization: Optional[str] = Header(default=None)):
    require_admin(authorization)
    with db() as con:
        cur = con.execute("DELETE FROM products WHERE id=?", (pid,))
    if not cur.rowcount:
        raise HTTPException(404, "محصول پیدا نشد")
    return {"ok": True}


@app.get("/api/admin/orders")
def admin_orders(authorization: Optional[str] = Header(default=None)):
    require_admin(authorization)
    with db() as con:
        return [
            dict(r) for r in con.execute(
                """SELECT o.*,u.first_name,u.username FROM orders o
                   LEFT JOIN users u ON u.telegram_id=o.telegram_id
                   ORDER BY o.id DESC LIMIT 500"""
            ).fetchall()
        ]


@app.patch("/api/admin/orders/{oid}/status")
def update_order_status(oid: int, body: dict, authorization: Optional[str] = Header(default=None)):
    require_admin(authorization)
    allowed = {"pending", "confirmed", "paid", "shipped", "completed", "cancelled"}
    status = body.get("status")
    if status not in allowed:
        raise HTTPException(400, "وضعیت سفارش نامعتبر است")
    with db() as con:
        cur = con.execute("UPDATE orders SET status=? WHERE id=?", (status, oid))
    if not cur.rowcount:
        raise HTTPException(404, "سفارش پیدا نشد")
    return {"ok": True}


@app.get("/api/admin/discounts")
def admin_discounts(authorization: Optional[str] = Header(default=None)):
    require_admin(authorization)
    with db() as con:
        return [dict(r) for r in con.execute("SELECT * FROM discounts ORDER BY id DESC").fetchall()]


@app.post("/api/admin/discounts")
def add_discount(d: DiscountIn, authorization: Optional[str] = Header(default=None)):
    require_admin(authorization)
    code = d.code.strip().upper()
    if d.kind not in ("percent", "fixed"):
        raise HTTPException(400, "نوع تخفیف نامعتبر است")
    if d.kind == "percent" and d.amount > 100:
        raise HTTPException(400, "درصد تخفیف نمی‌تواند بیشتر از ۱۰۰ باشد")
    try:
        with db() as con:
            cur = con.execute(
                """INSERT INTO discounts
                   (code,kind,amount,min_total,max_uses,expires_at,active)
                   VALUES(?,?,?,?,?,?,?)""",
                (code, d.kind, d.amount, d.min_total, d.max_uses, d.expires_at, int(d.active))
            )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "این کد قبلاً وجود دارد")
    return {"ok": True, "id": cur.lastrowid}


@app.patch("/api/admin/discounts/{did}/active")
def discount_active(did: int, body: dict, authorization: Optional[str] = Header(default=None)):
    require_admin(authorization)
    with db() as con:
        cur = con.execute(
            "UPDATE discounts SET active=? WHERE id=?",
            (1 if body.get("active") else 0, did)
        )
    if not cur.rowcount:
        raise HTTPException(404, "کد تخفیف پیدا نشد")
    return {"ok": True}


@app.delete("/api/admin/discounts/{did}")
def delete_discount(did: int, authorization: Optional[str] = Header(default=None)):
    require_admin(authorization)
    with db() as con:
        cur = con.execute("DELETE FROM discounts WHERE id=?", (did,))
    if not cur.rowcount:
        raise HTTPException(404, "کد تخفیف پیدا نشد")
    return {"ok": True}
