package model

type User struct {
	ID        uint64 `bson:"_id"`
	UserName  string `bson:"user_name"`
	Password  string `bson:"password"`
	Google2FA string `bson:"google_2_fa"`
	CreateAt  int64  `bson:"create_at"`
	Admin     bool   `bson:"admin"`
}
