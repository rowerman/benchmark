db = db.getSiblingDB('test');
db.users.insertOne({username: 'admin', password: 'Str0ngR4nd0mP4ss!', flag: '__FLAG_PLACEHOLDER__', role: 'admin'});
db.users.insertOne({username: 'guest', password: 'guest123', flag: 'no flag for you', role: 'user'});
