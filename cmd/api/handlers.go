package main

import (
	"errors"
	"fmt"
	"net/http"

	toolkit "github.com/mbilaljawwad/go-web-toolkit"
)

type RequestPayload struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (app *Config) Authenticate(w http.ResponseWriter, r *http.Request) {
	var tools toolkit.Tools
	var payload RequestPayload

	err := tools.ReadJSON(w, r, &payload)
	if err != nil {
		tools.ErrorJSON(w, err, http.StatusBadRequest)
	}

	// validate user by email
	user, err := app.Models.User.GetByEmail(payload.Email)
	if err != nil {
		tools.ErrorJSON(w, errors.New("invalid credentials"), http.StatusBadRequest)
	}

	// validate user by password
	valid, err := user.PasswordMatches(payload.Password)
	if err != nil || !valid {
		tools.ErrorJSON(w, errors.New("invalid credentials"), http.StatusBadRequest)
		return
	}

	successPayload := toolkit.JSONResponse{
		Error:   false,
		Message: fmt.Sprintf("Logged in user %s", user.Email),
		Data:    user,
	}

	tools.WriteJSON(w, http.StatusAccepted, successPayload)
}
