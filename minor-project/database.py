
import os
import hashlib
from datetime import datetime, timezone

from pymongo import MongoClient, ASCENDING, DESCENDING


# MongoDB configuration
MONGO_URI = os.getenv(
    "MONGO_URI",
    "mongodb://localhost:27017/"
)

DATABASE_NAME = "tls_mitre_siem"
COLLECTION_NAME = "security_events"

_client = None
_collection = None


def connect_database():
    """Connect to MongoDB and prepare the security events collection."""

    global _client, _collection

    if _collection is not None:
        return _collection

    _client = MongoClient(
        MONGO_URI,
        serverSelectionTimeoutMS=5000
    )

    # Verify MongoDB connection
    _client.admin.command("ping")

    database = _client[DATABASE_NAME]
    _collection = database[COLLECTION_NAME]

    # Create indexes for faster investigation
    _collection.create_index([("ja4", ASCENDING)])
    _collection.create_index([("ja4_sha256", ASCENDING)])
    _collection.create_index([("source_ip", ASCENDING)])
    _collection.create_index([("timestamp", DESCENDING)])
    _collection.create_index([("event_type", ASCENDING)])

    print("Connected to MongoDB successfully!")

    return _collection


def generate_ja4_hash(ja4_fingerprint):
    """Generate SHA-256 hash of the complete JA4 fingerprint."""

    if not isinstance(ja4_fingerprint, str) or not ja4_fingerprint:
        raise ValueError("A valid JA4 fingerprint is required.")

    return hashlib.sha256(
        ja4_fingerprint.encode("utf-8")
    ).hexdigest()


def store_event(event):
    """
    Store a security event.

    This generic function allows future event types
    to be stored in the same collection.
    """

    if not isinstance(event, dict):
        raise TypeError("Event must be a dictionary.")

    document = event.copy()

    # Generate a hash whenever a JA4 fingerprint is present
    ja4_fingerprint = document.get("ja4")

    if ja4_fingerprint:
        document["ja4_sha256"] = generate_ja4_hash(
            ja4_fingerprint
        )

    # Add default fields
    document.setdefault(
        "timestamp",
        datetime.now(timezone.utc)
    )

    document.setdefault(
        "event_category",
        "network" if ja4_fingerprint else "security"
    )

    collection = connect_database()

    result = collection.insert_one(document)

    print(f"Event stored successfully. ID: {result.inserted_id}")

    return str(result.inserted_id)


def store_ja4_event(event):
    """Store an event containing a JA4 fingerprint."""

    if not isinstance(event, dict):
        raise TypeError("Event must be a dictionary.")

    if not event.get("ja4"):
        raise ValueError("Event does not contain a JA4 fingerprint.")

    return store_event(event)


def close_database():
    """Close the MongoDB connection."""

    global _client, _collection

    if _client is not None:
        _client.close()

    _client = None
    _collection = None

    print("MongoDB connection closed.")

