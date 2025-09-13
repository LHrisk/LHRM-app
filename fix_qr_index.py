from pymongo import MongoClient

# Corrected MongoDB URI (removed '=' at the start)
client = MongoClient("mongodb+srv://crime_patrol_admin:s9FfOFiTwr8K82gI@cluster0.djti0hr.mongodb.net/crime_patrol_db?retryWrites=true&w=majority")
db = client["crime_patrol_db"]
collection = db["qr_locations"]

# Drop the old index on supervisorId ONLY
try:
    collection.drop_index("supervisorId_1")
    print("Dropped index: supervisorId_1")
except Exception as e:
    print("Index not found or already dropped:", e)