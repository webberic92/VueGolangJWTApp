package controllers

import (
	"strconv"
	"time"

	"example.com/m/database"
	"example.com/m/models"
	"github.com/coreos/go-oidc"
	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"

	"context"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

const secretKey = "adfasdfasdfasdf!@#$!#@$12342134"

func Register(c *fiber.Ctx) error {

	var data map[string]string
	c.BodyParser(&data)
	if err := c.BodyParser(&data); err != nil {
		return err
	}

	password, _ := bcrypt.GenerateFromPassword([]byte(data["password"]), 14)
	user := models.User{
		Name:     data["name"],
		Email:    data["email"],
		Password: password,
	}

	if data["name"] == "" {
		c.Status(fiber.StatusBadRequest)

		return c.JSON(fiber.Map{
			"message": "No name provided.",
		})
	}

	if data["email"] == "" {
		c.Status(fiber.StatusBadRequest)

		return c.JSON(fiber.Map{
			"message": "No email provided",
		})
	}
	if data["password"] == "" {
		c.Status(fiber.StatusBadRequest)

		return c.JSON(fiber.Map{
			"message": "No password provided.",
		})
	}

	if err := database.DB.Where("email = ?", data["email"]).First(&user).Error; err != nil {

		database.DB.Create(&user)
		return c.JSON(fiber.Map{
			"message": "You Successfully created a new user.",
		})

	} else {

		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{
			"message": "User already exsists with that Email.",
		})
	}

}

func Login(c *fiber.Ctx) error {
	var data map[string]string

	if err := c.BodyParser(&data); err != nil {
		return err
	}
	var user models.User
	database.DB.Where("email = ?", data["email"]).First(&user)

	if data["email"] == "" {
		c.Status(fiber.StatusBadRequest)

		return c.JSON(fiber.Map{
			"message": "Email can not be blank",
		})
	}

	if data["password"] == "" {
		c.Status(fiber.StatusBadRequest)

		return c.JSON(fiber.Map{
			"message": "password can not be blank",
		})
	}

	if user.Id == 0 {

		c.Status(fiber.StatusNotFound)
		return c.JSON(fiber.Map{
			"message": "Email does not exist",
		})
	}

	if err := bcrypt.CompareHashAndPassword(user.Password, []byte(data["password"])); err != nil {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(fiber.Map{

			"message": "Wrong password",
		})

	}

	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Issuer:    strconv.Itoa(int(user.Id)),
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
	})

	token, err := claims.SignedString([]byte(secretKey))

	if err != nil {

		c.Status(fiber.StatusInternalServerError)
		return c.JSON(fiber.Map{
			"message": "Could not login",
		})
	}

	cookie := fiber.Cookie{
		Name:     "jwt",
		Value:    token,
		Expires:  time.Now().Add(time.Hour * 24),
		HTTPOnly: true,
	}
	c.Cookie(&cookie)
	return c.JSON(fiber.Map{
		"message": "success",
	})
}

func KeyCloakLogin(c *fiber.Ctx) error {

	// create your oauth configuration
	config := oauth2.Config{
		ClientID: "admin-cli",
		Endpoint: oauth2.Endpoint{
			TokenURL: "http://localhost:8080/auth/realms/vueapp/protocol/openid-connect/token",
		},
	}

	// get a valid token from keycloak
	ctx := context.Background()
	token, err := config.PasswordCredentialsToken(ctx, "webbrico", "password")
	if err != nil {
		panic(err)
	}

	return c.JSON(fiber.Map{
		"message": token,
	})
}

func TestTokenIsValid(c *fiber.Ctx) error {

	configURL := "http://localhost:8080/auth/realms/vueapp"
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, configURL)
	if err != nil {
		panic(err)
	}

	clientID := "vueapp2"
	clientSecret := "214a04bb-80cb-4ba4-8249-ad60f609e41f"

	redirectURL := "http://localhost:8080/demo/callback"
	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),
		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}
	state := "somestate"

	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}
	verifier := provider.Verifier(oidcConfig)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		rawAccessToken := r.Header.Get("Authorization")
		if rawAccessToken == "" {
			http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
			return
		}

		parts := strings.Split(rawAccessToken, " ")
		if len(parts) != 2 {
			w.WriteHeader(400)
			return
		}
		_, err := verifier.Verify(ctx, parts[1])

		if err != nil {
			http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
			return
		}

		w.Write([]byte("hello world"))
	})
	return c.JSON("test")
}

func User(c *fiber.Ctx) error {
	cookie := c.Cookies("jwt")

	token, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil {
		c.Status(fiber.StatusUnauthorized)
		return c.JSON(fiber.Map{
			"message": "Unauthenticated User",
		})
	}
	claims := token.Claims.(*jwt.StandardClaims)
	var user models.User

	database.DB.Where("id = ?", claims.Issuer).First(&user)

	return c.JSON(user)

}

func Logout(c *fiber.Ctx) error {

	User(c)

	if c.Response().StatusCode() == 401 {
		return c.JSON(fiber.Map{
			"message": "Cant logout, User not even logged in.",
		})
	} else {
		cookie := fiber.Cookie{
			Name:     "jwt",
			Value:    "",
			Expires:  time.Now().Add(-time.Hour),
			HTTPOnly: true,
		}

		c.Cookie(&cookie)
		return c.JSON(fiber.Map{
			"message": "Logout successful",
		})
	}

}
