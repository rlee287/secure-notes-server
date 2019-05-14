from secure_notes_server import users_db, notes_db

#could be broken
class User(users_db.Document):
    username=users_db.StringField()
    notelist=users_db.ListField(notes_db.ObjectIdField())

class Note(notes_db.Document):
    title=notes_db.BinaryField()
    userlist=notes_db.ListField(users_db.ObjectIdField())
    modified=notes_db.DateTimeField()
    text=notes_db.BinaryField()
