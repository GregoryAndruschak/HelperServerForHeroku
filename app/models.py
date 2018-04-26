from sqlalchemy.ext.hybrid import hybrid_property, hybrid_method

from app import db, bcrypt


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.BigInteger, primary_key=True)
    username = db.Column(db.String(16), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    high_score_id = db.Column(db.BigInteger, db.ForeignKey('highscores.id'), nullable=False)
    high_score = db.relationship('Highscore',backref=db.backref('users', lazy=True))

    def __init__(self, username, email, plaintext_password):
        self.username = username
        self.email = email
        self.set_password = plaintext_password

    @hybrid_property
    def ppassword(self):
        return self.password

    @ppassword.setter
    def set_password(self, plaintext_password):
        self.password = bcrypt.generate_password_hash(plaintext_password)

    @hybrid_method
    def is_correct_password(self, plaintext_password):
        return bcrypt.check_password_hash(self.ppassword, plaintext_password)

    def __repr__(self):
        return '<User {}>'.format(self.username)


class Highscore(db.Model):
    __tablename__ = "highscores"

    id = db.Column(db.BigInteger, primary_key=True)
    deathalltime = db.Column(db.Integer, nullable=False)
    deathlastmonth = db.Column(db.Integer, nullable=False)
    deathlastweek = db.Column(db.Integer, nullable=False)
    gamesalltime = db.Column(db.Integer, nullable=False)
    gameslastmonth = db.Column(db.Integer, nullable=False)
    gameslastweek = db.Column(db.Integer, nullable=False)
    raiting = db.Column(db.Integer, nullable=False)
    raitingmonth = db.Column(db.Integer, nullable=False)
    raitingweek = db.Column(db.Integer, nullable=False)
    winsalltime = db.Column(db.Integer, nullable=False)
    winslastmonth = db.Column(db.Integer, nullable=False)
    winslastweek = db.Column(db.Integer, nullable=False)

    def __init__(self, deathalltime, deathlastmonth, deathlastweek, gamesalltime, gameslastmonth, gameslastweek, rating, ratingmonth, ratingweek, winsalltime, winslastmonth, winslastweek):
        self.deathalltime = deathalltime
        self.deathlastmonth = deathlastmonth
        self.deathlastweek = deathlastweek
        self.gamesalltime = gamesalltime
        self.gameslastmonth = gameslastmonth
        self.gameslastweek = gameslastweek
        self.raiting = rating
        self.raitingmonth = ratingmonth
        self.raitingweek = ratingweek
        self.winsalltime = winsalltime
        self.winslastmonth = winslastmonth
        self.winslastweek = winslastweek


