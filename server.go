package main

import (
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"context"

	"github.com/go-playground/validator/v10"
	"github.com/go-rod/rod"
	"github.com/gorilla/sessions"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
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
	Id           string    `json:"id"`
	Url          string    `json:"url"`
	Body         string    `json:"body"`
	Age          time.Time `json:"age"`
	UserId       string    `json:"userId"`
	CollectionId []string  `json:"collectionId"`
}

type Collection struct {
	Id         string    `json:"id"`
	Curator    string    `json:"curator"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
	Visibility bool      `json:"visibility"`
	UserId     string    `json:"userId"`
	Score      float64   `json:"score"`
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
		Id   string `json:"id"`
		Data string `json:"data"`
	}

	CollectionResponse struct {
		Id       string             `json:"id"`
		Curator  string             `json:"name"`
		Data     string             `json:"data"`
		WebItems []*WebItemResponse `json:"items"`
	}

	HomeResponse struct {
		User        UserResponse          `json:"user"`
		Collections []*CollectionResponse `json:"collections"`
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

func createUser(ctx context.Context, db *pgxpool.Pool, user User) error {

	cctx, cancel := context.WithTimeout(ctx, time.Second*2)
	defer cancel()
	stmt := "INSERT INTO users(id,username, email, password_digest) VALUES ($1, $2, $3, $4)"

	if _, err := db.Exec(cctx, stmt, user.id, user.username, user.email, user.password_digest); err != nil {
		log.Errorf("error - creating user %v", err)
		return err
	}
	return nil
}

func (workItem *HnWorkItem) hnImportProcessing(ctx context.Context, db *pgxpool.Pool) error {

	cctx, cancel := context.WithTimeout(ctx, time.Second*2)
	defer cancel()

	createCollectionQuery := `
		INSERT INTO collections(id, user_id, curator, data) 
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id, curator)
		DO NOTHING
		RETURNING id
	`
	createWebItemQuery := `
		INSERT INTO web_items(id, user_id, collection_id, url, data) 
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (collection_id, url) 
		DO NOTHING
		RETURNING id
	`

	tx, err := db.Begin(cctx)
	if err != nil {
		log.Errorf("failed to start db transaction, %v", err)
		return err
	}
	defer tx.Rollback(cctx)
	collection := Collection{Id: ulid.Make().String(), Curator: workItem.curator, Visibility: false, UserId: workItem.userId, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	collectionCreateError := tx.QueryRow(cctx, createCollectionQuery, collection.Id, collection.UserId, collection.Curator, collection).Scan(&collection.Id)
	if collectionCreateError != nil {
		if rollbackErr := tx.Rollback(cctx); rollbackErr != nil {
			log.Errorf("failed to create collection %v, failed to rollback %v", collectionCreateError, rollbackErr)
			return rollbackErr
		}
		log.Errorf("failed to create collection %v", collectionCreateError)
		return collectionCreateError
	}
	for _, webItem := range workItem.webItems {
		webItem.CollectionId = append(webItem.CollectionId, collection.Id)
		webItemCreateError := tx.QueryRow(cctx, createWebItemQuery, webItem.Id, workItem.userId, collection.Id, webItem.Url, webItem).Scan(&webItem.Id)
		if webItemCreateError != nil {
			if rollbackErr := tx.Rollback(cctx); rollbackErr != nil {
				log.Errorf("failed to create WebItem %v, failed to rollback %v", webItemCreateError, rollbackErr)
				return rollbackErr
			}
			log.Errorf("failed to create WebItem %v", webItemCreateError)
			return webItemCreateError
		}

	}
	if err := tx.Commit(cctx); err != nil {
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
		comment := WebItem{Id: ulid.Make().String()}
		comment.extractComment(link)
		commentsList = append(commentsList, comment)
	}

	return commentsList
}

func (c *WebItem) extractComment(link *rod.Element) {
	body, err := link.Element(".comment")
	if err != nil {
		log.Printf("could not extract body")
	}
	c.Body = body.MustText()
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
	c.Age = ageTime
	c.Url = "https://news.ycombinator.com/" + *url
}

//func deleteUser(db {}, user string) {}

func login(ctx context.Context, db *pgxpool.Pool, username string) (u User, err error) {
	var user User
	stmt := `
		SELECT id, username, email, password_digest, created_at, updated_at
		FROM users
		WHERE username=$1
	`
	cctx, cancel := context.WithTimeout(ctx, time.Second*2)
	defer cancel()

	err = db.QueryRow(cctx, stmt, username).Scan(&user.id,
		&user.username,
		&user.email,
		&user.password_digest,
		&user.created_at,
		&user.updated_at)

	switch {
	case err == sql.ErrNoRows:
		return User{}, nil
	case err != nil:
		return User{}, err
	default:
		return user, nil
	}
}

func home(ctx context.Context, db *pgxpool.Pool, userId string) (HomeResponse, error) {

	cctx, cancel := context.WithTimeout(ctx, time.Second*2)
	defer cancel()

	var homeResponse HomeResponse
	var userResponse UserResponse
	var collections []*CollectionResponse

	if userId != "" {

		userQuery := `SELECT id, username
		FROM users
		WHERE id = $1`

		userCollectionsQuery := ` SELECT id, curator, data
		FROM collections
		WHERE user_id = $1
		`

		webItemsInCollectionQuery := `SELECT id, data
		FROM web_items 
		WHERE collection_id = $1
		`

		tx, err := db.Begin(cctx)
		if err != nil {
			log.Errorf("could not start db transaction, %v", err)
		}
		defer tx.Rollback(cctx)

		userFetchErr := db.QueryRow(cctx, userQuery, userId).Scan(&userResponse.Id, &userResponse.Username)

		if userFetchErr != nil {
			if rollbackErr := tx.Rollback(cctx); rollbackErr != nil {
				log.Errorf("failed to get user %v, failed to rollback %v", userFetchErr, rollbackErr)
				return HomeResponse{}, rollbackErr
			}
			log.Errorf("failed to get user %v", userFetchErr)
			return HomeResponse{}, userFetchErr
		}

		collectionRows, collectionFetchErr := db.Query(cctx, userCollectionsQuery, userId)

		if collectionFetchErr != nil {
			if rollbackErr := tx.Rollback(cctx); rollbackErr != nil {
				log.Errorf("failed to get collections %v, failed to rollback %v", collectionFetchErr, rollbackErr)
				return HomeResponse{}, rollbackErr
			}
			log.Errorf("failed to get collections %v", collectionFetchErr)
			return HomeResponse{}, collectionFetchErr
		}

		defer collectionRows.Close()

		for collectionRows.Next() {
			collection := &CollectionResponse{}
			rowErr := collectionRows.Scan(&collection.Id, &collection.Curator, &collection.Data)
			if rowErr != nil {
				if rollbackErr := tx.Rollback(cctx); rollbackErr != nil {
					log.Errorf("failed to scan collections %v, failed to rollback %v", rowErr, rollbackErr)
					return HomeResponse{}, rollbackErr
				}
				log.Errorf("failed to scan collections %v", rowErr)
				return HomeResponse{}, rowErr
			}
			collections = append(collections, collection)
		}

		if collectionRows.Err() != nil {
			if rollbackErr := tx.Rollback(cctx); rollbackErr != nil {
				log.Errorf("collection row error %v, failed to rollback %v", collectionRows.Err(), rollbackErr)
				return HomeResponse{}, rollbackErr
			}
			log.Errorf("collection row error %v", collectionRows.Err())
			return HomeResponse{}, collectionRows.Err()
		}

		for _, collection := range collections {

			webItemRows, webItemFetchErr := tx.Query(cctx, webItemsInCollectionQuery, collection.Id)

			if webItemFetchErr != nil {
				if rollbackErr := tx.Rollback(cctx); rollbackErr != nil {
					log.Errorf("failed to get webItems %v, failed to rollback %v", webItemFetchErr, rollbackErr)
					return HomeResponse{}, rollbackErr
				}
				log.Errorf("failed to get webItems %v", webItemFetchErr)
				return HomeResponse{}, webItemFetchErr
			}

			defer webItemRows.Close()

			for webItemRows.Next() {
				var webItem WebItemResponse
				var webItems []*WebItemResponse
				rowErr := webItemRows.Scan(&webItem.Id, &webItem.Data)
				if rowErr != nil {
					if rollbackErr := tx.Rollback(cctx); rollbackErr != nil {
						log.Errorf("failed to scan webItem row %v, failed to rollback %v", rowErr, rollbackErr)
						return HomeResponse{}, rollbackErr
					}
					log.Errorf("failed to scan webItem row %v", rowErr)
					return HomeResponse{}, rowErr
				}
				webItems = append(webItems, &webItem)
				collection.WebItems = append(collection.WebItems, webItems...)
			}

			if webItemRows.Err() != nil {
				if rollackErr := tx.Rollback(cctx); rollackErr != nil {
					log.Errorf("webItems row error %v, failed to rollback %v", webItemRows.Err(), rollackErr)
					return HomeResponse{}, rollackErr
				}
				log.Errorf("webItems row error %v", webItemRows.Err())
				return HomeResponse{}, webItemRows.Err()
			}
		}
		homeResponse.User = userResponse
		homeResponse.Collections = collections
		return homeResponse, nil
	}
	return HomeResponse{}, nil
}

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
	DB *pgxpool.Pool
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

	ctx := context.Background()

	// save user
	if err := createUser(ctx, h.DB, user); err != nil {
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

	ctx := context.Background()

	user, err := login(ctx, h.DB, loginDetails.Username)
	if err != nil {
		return c.NoContent(http.StatusInternalServerError)
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.password_digest), []byte(loginDetails.Password))
	if err != nil {
		return c.NoContent(http.StatusUnauthorized)
	}

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

	return c.NoContent(http.StatusOK)
}

func (h *Handler) homeHandler(c echo.Context) error {
	ctx := context.Background()
	if userId, ok := c.Get("currentUser").(string); ok {
		user := User{id: userId}
		homeResponse, err := home(ctx, h.DB, user.id)
		if err != nil {
			return c.NoContent(http.StatusInternalServerError)
		}
		return c.JSON(http.StatusOK, homeResponse)
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

	ctx := context.Background()

	query := parsedUrl.Query()
	curator := query.Get("id")
	comments := getHNComments(u)
	if userId, ok := c.Get("currentUser").(string); ok {
		user := User{id: userId}
		workItem := &HnWorkItem{curator: curator, webItems: comments, userId: user.id}
		workItem.hnImportProcessing(ctx, h.DB)
	}

	// do this in background later
	log.Printf("curator %v", curator)

	return c.NoContent(http.StatusCreated)
}

func authenticate(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if c.Path() != "/login" && c.Path() != "/signup" {
			log.Printf("called from IF")
			sess, err := session.Get("session", c)
			currentUser := sess.Values["currentUser"]
			log.Printf("current User %v", currentUser)
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

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	ctx := context.Background()

	db, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatalf("unable to create connection pool %v", err)
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
