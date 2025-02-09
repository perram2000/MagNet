import pymongo
import os

# MongoDB 客户端配置
client = pymongo.MongoClient("")
db = client["monitorsolutions"]


def getSettings():
    """
    从数据库中获取设置。
    """
    try:
        settings = db.settings.find_one()
        if not settings:
            print("[DATABASE] No settings found in the database.")
        return settings
    except Exception as e:
        print(f"[DATABASE] Failed to load settings: {e}")
        return None


def initializeSettings():
    """
    初始化默认设置到数据库。
    """
    try:
        db.settings.insert_one({
            "canyon": {"delay": 30},
            "shopify": {"keywords": [], "proxys": "", "delay": 10}
        })
        print("[DATABASE] Default settings initialized.")
    except Exception as e:
        print(f"[DATABASE] Failed to initialize settings: {e}")


def getItems():
    """
    获取数据库中已存储的商品列表。
    """
    try:
        items = db.canyon_items.find()
        return {item["title"] for item in items}  # 返回商品标题集合
    except Exception as e:
        print(f"[DATABASE] Failed to retrieve items: {e}")
        return set()


def insertNewItem(item):
    """
    将新商品插入数据库。
    """
    try:
        db.canyon_items.insert_one(item)
        print(f"[DATABASE] New item added: {item['title']}")
    except Exception as e:
        print(f"[DATABASE] Failed to insert new item: {e}")