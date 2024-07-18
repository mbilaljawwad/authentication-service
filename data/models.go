package data

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const dbTimeout = time.Second * 3

var db *sql.DB

type User struct {
	ID        int       `json:"id"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name,omitempty"`
	LastName  string    `json:"last_name,omitempty"`
	Password  string    `json:"-"`
	Active    int       `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Models struct {
	User User
}

func New(database *sql.DB) Models {
	db = database

	return Models{
		User: User{},
	}
}

func (u *User) GetAll() ([]*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	query := `SELECT * FROM users ORDER BY last_name`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User

	for rows.Next() {
		var user User
		err := scanUserRows(rows, &user)
		if err != nil {
			log.Println("Error occurs on scanning rows in GetAll() method: ", err)
			return nil, err
		}
		users = append(users, &user)
	}

	return users, nil
}

func (u *User) GetByEmail(email string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	row := db.QueryRowContext(
		ctx,
		`SELECT * FROM users WHERE email = $1`,
		email,
	)

	var user User
	err := row.Scan(
		&user.ID,
		&user.Email,
		&user.FirstName,
		&user.LastName,
		&user.Password,
		&user.Active,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		log.Println("Error occurs on scanning row in GetByEmail() method: ", err)
		return nil, err
	}
	return &user, nil
}

func (u *User) GetOne(id int) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	rows, err := db.QueryContext(
		ctx,
		`SELECT * FROM users WHERE id = $1`,
		id,
	)
	if err != nil {
		return nil, err
	}

	var user User
	err = scanUserRows(rows, &user)
	if err != nil {
		return nil, err
	}

	return &user, nil

}

func (u *User) Update() error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	_, err := db.ExecContext(
		ctx,
		`UPDATE users
		SET email = $1, first_name - $2, last_name = $3, user_active = $4, updated_at = $5
		WHERE id = $6`,
		u.Email, u.FirstName, u.LastName, u.Active, time.Now(), u.ID,
	)

	if err != nil {
		return err
	}
	return nil
}

func (u *User) Delete() error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	_, err := db.ExecContext(
		ctx,
		`DELETE FROM user WHERE id = $1`,
		u.ID,
	)
	if err != nil {
		return err
	}
	return nil
}

func (u *User) DeleteById(id int) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	_, err := db.ExecContext(
		ctx,
		`DELETE FROM user WHERE id = $1`,
		id,
	)
	if err != nil {
		return err
	}
	return nil
}

func (u *User) Insert() (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), 12)
	if err != nil {
		return 0, err
	}

	result, err := db.ExecContext(
		ctx,
		`INSERT INTO users (email, first_name, last_name, password, user_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		u.Email, u.FirstName, u.LastName, hashedPassword, u.Active, time.Now(), time.Now(),
	)

	if err != nil {
		return 0, err
	}

	newId, err := result.LastInsertId()
	if err != nil {
		log.Println("Error occurs on getting last insert id in Insert() method: ", err)
		return 0, err
	}

	return int(newId), nil
}

func (u *User) ResetPassword(password string) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return err
	}

	_, err = db.ExecContext(ctx, `UPDATE users SET password = $1 WHERE id = $2`, hashedPassword, u.ID)
	if err != nil {
		return err
	}

	return nil
}

func (u *User) PasswordMatches(pwd string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(pwd))
	if err != nil {
		switch {
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			return false, nil
		default:
			return false, err
		}
	}
	return true, nil
}

func scanUserRows(rows *sql.Rows, user *User) error {
	err := rows.Scan(
		&user.ID,
		&user.Email,
		&user.FirstName,
		&user.LastName,
		&user.Password,
		&user.Active,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return err
	}

	return nil
}
