package main

import (
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/go-playground/validator/v10"
	"github.com/go-rod/rod"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"github.com/oklog/ulid/v2"
	"golang.org/x/crypto/bcrypt"
)

// models
type User struct {
	id              string
	email           string
	username        string
	password_digest string
	created_at      time.Time //time
	updated_at      time.Time // time
}

type Session struct {
	id        string
	userId    string
	expiresAt time.Time
}

type WebItem struct {
	id     string
	url    string
	body   string
	age    time.Time
	userId string
}

type Collection struct {
	id         string
	curator    string
	createdAt  time.Time
	updatedAt  time.Time
	visibility bool
	userId     string
}

type HnWorkItem struct {
	webItems []WebItem
	curator  string
	userId   string
}

type (
	SignupDetails struct {
		Email    string `json:"email" validate:"required,email"`
		Username string `json:"username" validate:"required,gte=3,lte=20"`
		Password string `json:"password" validate:"required,gte=8"`
	}

	LoginDetails struct {
		Username string `json:"username" validate:"required,gte=3,lte=20"`
		Password string `json:"password" validate:"required"`
	}

	HNImportDetails struct {
		Url string `json:"url" validate:"required,http_url"`
	}

	CustomValidator struct {
		validator *validator.Validate
	}
)

// Response types
type (
	LoginResponse struct {
		Username string `json:"username"`
		Token    string `json:"token"`
	}

	UserResponse struct {
		Id        string    `json:"id"`
		Username  string    `json:"username"`
		Email     string    `json:"email"`
		CreatedAt time.Time `json:"createdAt"`
		UpdatedAt time.Time `json:"updatedAt"`
	}

	WebItemResponse struct {
		Id     string    `json:"id"`
		Url    string    `json:"url"`
		Body   string    `json:"body"`
		Source string    `json:"source"`
		Age    time.Time `json:"age"`
	}

	CollectionResponse struct {
		Id         string    `json:"id"`
		Curator    string    `json:"name"`
		CreatedAt  time.Time `json:"createdAt"`
		UpdatedAt  time.Time `json:"updatedAt"`
		Visibility bool      `json:"private"`
	}

	HomeResponse struct {
		User        UserResponse         `json:"user"`
		Collections []CollectionResponse `json:"collections"`
	}
)

// validation
func (cv *CustomValidator) Validate(i interface{}) error {
	if err := cv.validator.Struct(i); err != nil {
		var ve validator.ValidationErrors
		errorsMap := make(map[string]string)
		if errors.As(err, &ve) {
			for _, item := range ve {
				errorsMap[item.Field()] = msgForTag(item.Tag())
			}
			return echo.NewHTTPError(http.StatusUnprocessableEntity, errorsMap)
		}
	}
	return nil
}

// helper function for validation
func msgForTag(tag string) string {
	switch tag {
	case "required":
		return "this is required"
	case "email":
		return "email required"
	case "gte":
		return "wrong length"
	case "lte":
		return "wrong length"
	}
	return ""
}

//---------
// Core Functionality
//---------

func createUser(db *sql.DB, user User) error {

	stmt, err := db.Prepare("INSERT INTO users(id,username, email, password_digest) VALUES (?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	if _, err := stmt.Exec(user.id, user.username, user.email, user.password_digest); err != nil {
		return err
	}
	return nil
}

/* func createSession(db *sql.DB, session Session) error {
	stmt, err := db.Prepare("INSERT INTO sessions(id, user_id, expires_at) VALUES (?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	if _, err := stmt.Exec(session.id, session.userId, session.expiresAt); err != nil {
		return err
	}
	return nil
} */

func (workItem *HnWorkItem) hnImportProcessing(db *sql.DB) error {
	const createCollectionQuery = `
		INSERT OR IGNORE INTO collections(id, curator, user_id, visibility) VALUES (?, ?, ?, ?)
		RETURNING id
	`
	const createWebItemQuery = `
		INSERT OR IGNORE INTO web_items(id, url, body, age, user_id) VALUES (?, ?, ?, ?, ?)
		RETURNING id
	`
	const createWebColletionsQuery = `
		INSERT OR IGNORE INTO web_collections(web_item_id, collection_id) VALUES (?, ?)
	`
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	collection := Collection{id: ulid.Make().String(), curator: workItem.curator, visibility: false, userId: workItem.userId}
	collectionCreateError := tx.QueryRow(createCollectionQuery, collection.id, collection.curator, collection.userId, collection.visibility).Scan(&collection.id)
	if collectionCreateError != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			log.Errorf("failed to create collection %v, failed to rollback %v", collectionCreateError, rollbackErr)
			return rollbackErr
		}
		log.Errorf("failed to create collection %v", collectionCreateError)
		return collectionCreateError
	}
	for _, webItem := range workItem.webItems {
		webItemCreateError := tx.QueryRow(createWebItemQuery, webItem.id, webItem.url, webItem.body, webItem.age, workItem.userId).Scan(&webItem.id)
		if webItemCreateError != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				log.Errorf("failed to create WebItem %v, failed to rollback %v", webItemCreateError, rollbackErr)
				return rollbackErr
			}
			log.Errorf("failed to create WebItem %v", webItemCreateError)
			return webItemCreateError
		}
		_, webCollectionError := tx.Exec(createWebColletionsQuery, webItem.id, collection.id)
		if webCollectionError != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				log.Errorf("failed to create webCollection %v, failed to rollback %v", webCollectionError, rollbackErr)
				return rollbackErr
			}
			log.Errorf("failed to create webCollection %v", webCollectionError)
			return webCollectionError
		}
	}
	if err := tx.Commit(); err != nil {
		log.Errorf("failed to create webItems & collecton", err)
	}
	return nil
}

func getHNComments(url string) []WebItem {
	page := rod.New().NoDefaultDevice().MustConnect().MustPage(url)
	links := page.MustElements(".athing")
	return generateCommentsList(links)
}

func generateCommentsList(links rod.Elements) []WebItem {
	commentsList := []WebItem{}

	for _, link := range links {
		comment := WebItem{id: ulid.Make().String()}
		comment.extractComment(link)
		commentsList = append(commentsList, comment)
	}

	for _, comment := range commentsList {
		log.Printf("%+v", comment)
	}
	return commentsList
}

func (c *WebItem) extractComment(link *rod.Element) {
	body, err := link.Element(".comment")
	if err != nil {
		log.Printf("could not extract body")
	}
	c.body = body.MustText()
	urlElement, _ := link.Element(".age > a")
	url, err := urlElement.Attribute("href")
	if err != nil {
		log.Errorf("could not extract link")
	}
	spanElement, _ := link.Element(".age")
	age, err := spanElement.Attribute("title")
	if err != nil {
		log.Errorf("could not extract age")
	}
	log.Printf("age %v", *age)
	ageTime, err := time.Parse("2006-01-02T15:04:05", *age)
	if err != nil {
		log.Errorf("could not parse time")
	}
	c.age = ageTime
	c.url = "https://news.ycombinator.com/" + *url
}

//func deleteUser(db {}, user string) {}

func login(db *sql.DB, username string) (u User, err error) {
	var user User
	stmt, err := db.Prepare(`
		SELECT id, username, email, password_digest, created_at, updated_at
		FROM users
		WHERE username=?
	`)

	if err != nil {
		return User{}, err
	}

	err = stmt.QueryRow(username).Scan(&user.id,
		&user.username,
		&user.email,
		&user.password_digest,
		&user.created_at,
		&user.updated_at)

	defer stmt.Close()

	switch {
	case err == sql.ErrNoRows:
		return User{}, nil
	case err != nil:
		return User{}, err
	default:
		return user, nil
	}
}

func home(db *sql.DB, userId string) error {
	if userId != "" {
		const userQuery = `SELECT id, username
		FROM users
		WHERE user_id = ?`
		const userItemsQuery = `SELECT w.id, w.url, COALESCE(w.source, ''), w.body, w.age, c.id, c.curator, c.created_at, c.updated_at, c.visibility
		FROM web_items w, collections c, web_collections wc
		WHERE w.user_id = ?
		AND   c.user_id=w.user_id
		AND   wc.collection_id = c.id 
		AND   wc.web_item_id = w.id
		`
		userResponse := &UserResponse{}
		collections := []CollectionResponse{}
		err := db.QueryRow(userQuery, userId).Scan(&userResponse.Id, &userResponse.Username)

		switch {
		case err == sql.ErrNoRows:
			log.Errorf("no data for user %v", userId)
		case err != nil:
			log.Errorf("ran into error getting user data %v", userId)
		default:
			log.Printf("user found")
		}

		rows, err := db.Query(userItemsQuery, userId)
		if err != nil {
			log.Errorf("could not return user web_items / collections query %v", err)
			return err
		}

		for rows.Next() {
			var (
				collection CollectionResponse
				webItem    WebItemResponse
			)
			if err := rows.Scan(&webItem.Id, &webItem.Url, &webItem.Source, &webItem.Body, &webItem.Age, &collection.Id, &collection.Curator, &collection.CreatedAt, &collection.UpdatedAt, &collection.Visibility); err != nil {
				log.Errorf("could not retrieve rows %v", err)
				return err
			}
			collections = append(collections, collection)
			log.Printf("item %v, in collection %v", webItem, collection)
		}
		return nil

	}
	return nil
}

/* func getSession(db *sql.DB, key string) (string, error) {
	var userId string
	stmt, err := db.Prepare(`
		SELECT user_id
		FROM sessions
		WHERE id=?
	`)
	if err != nil {
		return "", err
	}

	err = stmt.QueryRow(key).Scan(&userId)

	defer stmt.Close()

	switch {
	case err == sql.ErrNoRows:
		return "", err
	case err != nil:
		return "", err
	default:
		return userId, nil
	}
} */

// --------
// Helpers
// --------
/* func generateToken() string {
	b := make([]byte, 13)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	hexString := hex.EncodeToString(b)
	return hexString
} */

//---------
// Handlers
//---------

type Handler struct {
	DB *sql.DB
}

func (h *Handler) signupHandler(c echo.Context) error {
	signupDetails := new(SignupDetails)
	if err := c.Bind(signupDetails); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	if err := c.Validate(signupDetails); err != nil {
		return err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(signupDetails.Password), 10)

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "sorry, we ran into some issues"})
	}

	user := User{
		id:              ulid.Make().String(),
		username:        signupDetails.Username,
		email:           signupDetails.Email,
		password_digest: string(hashedPassword),
	}

	// save user
	if err := createUser(h.DB, user); err != nil {
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.NoContent(http.StatusOK)
}

func (h *Handler) loginHandler(c echo.Context) error {
	loginDetails := new(LoginDetails)
	if err := c.Bind(loginDetails); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	if err := c.Validate(loginDetails); err != nil {
		return err
	}
	user, err := login(h.DB, loginDetails.Username)
	if err != nil {
		return c.NoContent(http.StatusInternalServerError)
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.password_digest), []byte(loginDetails.Password))
	if err != nil {
		return c.NoContent(http.StatusUnauthorized)
	}

	//token := generateToken()
	//expiryTime := time.Now().Add(time.Hour * 24)
	//session := Session{id: token, userId: user.id, expiresAt: expiryTime}

	sess, err := session.Get("session", c)
	if err != nil {
		return err
	}
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
	}
	sess.Values["currentUser"] = user.id
	if err := sess.Save(c.Request(), c.Response()); err != nil {
		return err
	}

	/* if err := createSession(h.DB, session); err != nil {
		return c.NoContent(http.StatusInternalServerError)
	} */

	//loginResponse := LoginResponse{Token: token, Username: user.username}
	//return c.JSON(http.StatusOK, loginResponse)
	return c.NoContent(http.StatusOK)
}

func (h *Handler) homeHandler(c echo.Context) error {
	if userId, ok := c.Get("currentUser").(string); ok {
		user := User{id: userId}
		home(h.DB, user.id)
		return c.NoContent(http.StatusOK)
	}
	return nil
}

func (h *Handler) importFromHN(c echo.Context) error {
	hnImportDetails := new(HNImportDetails)
	if err := c.Bind(hnImportDetails); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	if err := c.Validate(hnImportDetails); err != nil {
		return err
	}
	u := hnImportDetails.Url
	parsedUrl, err := url.Parse(u)
	if err != nil {
		return err
	}
	query := parsedUrl.Query()
	curator := query.Get("id")
	comments := getHNComments(u)
	if userId, ok := c.Get("currentUser").(string); ok {
		user := User{id: userId}
		workItem := &HnWorkItem{curator: curator, webItems: comments, userId: user.id}
		workItem.hnImportProcessing(h.DB)
	}

	// do this in background later
	log.Printf("curator %v", curator)

	return c.NoContent(http.StatusCreated)
}

func authenticate(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		log.Printf("path %v", c.Path() == "/login")
		if c.Path() != "/login" && c.Path() != "/signup" {
			log.Printf("called from IF")
			sess, err := session.Get("session", c)
			currentUser := sess.Values["currentUser"]
			c.Set("currentUser", currentUser)
			if err != nil || currentUser == nil {
				return c.NoContent(http.StatusUnauthorized)
			}
			return next(c)
		}
		return next(c)
	}
}

func CorsHeader(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set("Access-Control-Allow-Origin", "http://localhost:5175/")
		c.Response().Header().Set("Access-Control-Allow-Origin", "http://localhost:5175/")
		c.Response().Header().Set("Access-Control-Allow-Origin", "*")
		c.Response().Header().Set("Access-Control-Allow-Origin", "http://localhost:5175")
		return next(c)
	}
}

func main() {

	db, err := sql.Open("sqlite3", "./db/8kur.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	e := echo.New()

	//middleware
	e.Logger.SetLevel(log.ERROR)
	e.Use(middleware.Logger())
	e.Use(session.Middleware(sessions.NewCookieStore([]byte("secret"))))
	e.Use(CorsHeader)
	//e.Use(middleware.CORS())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     []string{"http://localhost:5174", "http://localhost:5175", "*"},
		AllowMethods:     []string{http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete, http.MethodOptions},
		AllowCredentials: true,
		AllowHeaders: []string{
			echo.HeaderAccessControlAllowMethods,
			echo.HeaderAccessControlAllowOrigin,
			echo.HeaderAccessControlAllowCredentials,
			echo.HeaderAccept,
			echo.HeaderContentType,
			echo.HeaderXContentTypeOptions,
			echo.HeaderOrigin,
			"X-PINGOTHER",
		},
	}))
	e.Use(authenticate)

	e.Validator = &CustomValidator{validator: validator.New()}

	h := &Handler{DB: db}

	e.GET("/hello", func(c echo.Context) error {
		return c.String(http.StatusOK, "hello world!!")
	})
	e.POST("/login", h.loginHandler)
	e.POST("/signup", h.signupHandler)
	e.POST("/hn-import", h.importFromHN)
	e.GET("/home", h.homeHandler)
	e.Logger.Fatal(e.Start(":1323"))
}
