db = db.getSiblingDB('flags');
db.flag_collection.insertOne({flag: '__CVE_FLAG__', note: 'Find me!'});
