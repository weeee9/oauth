package controllers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/google"

	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
)

type credential struct {
	Client string `json:"clientid"`
	Secret string `json:"secret"`
}

type appErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type oauthUser struct {
	Sub     string `json:"sub"`
	Name    string `json:"name"`
	Profile string `json:"profile"`
	Picture string `json:"picture"`
	Email   string `json:"email"`
}

// your oauth redirect url
var redirURL = map[string]string{
	"google":   "http://localhost:8080/oauth/google/callback",
	"facebook": "http://localhost:8080/oauth/facebook/callback",
}

// your oauth credential file path
//
// see your_clientID.json
var cred = map[string]string{
	"google":   "./google.clientID.json",
	"facebook": "./facebook.clientID.json",
}

// provider's api
var oauthAPI = map[string]string{
	"google":   "https://www.googleapis.com/oauth2/v3/userinfo",
	"facebook": "https://graph.facebook.com/me?access_token=",
}

// select your own scope here
// https://developers.google.com/identity/protocols/googlescopes#google_sign-in
var googleScopes = []string{
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/userinfo.profile",
}

// select your own scope here
// https://developers.facebook.com/docs/facebook-login/permissions
var facebookScopes = []string{
	"public_profile,email",
}

var googleConfig = setup(redirURL["google"], cred["google"], googleScopes, google.Endpoint)
var facebookConfig = setup(redirURL["facebook"], cred["facebook"], facebookScopes, facebook.Endpoint)

var oauthConfig = map[string]*oauth2.Config{
	"google":   googleConfig,
	"facebook": facebookConfig,
}

// OauthRedirect ...
func OauthRedirect(c *gin.Context) {
	provider := c.Param("provider")
	state := randToken()
	if _, ok := oauthConfig[provider]; !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": appErr{
				Code:    http.StatusBadRequest,
				Message: "Invalid Provider",
			},
		})
		return
	}
	url := oauthConfig[provider].AuthCodeURL(state)
	c.SetCookie("oauth_state", state, 360, "", "", false, true)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// OauthCallback ...
func OauthCallback(c *gin.Context) {
	provider := c.Param("provider")
	code := c.Query("code")
	state := c.Query("state")
	cookie, err := c.Cookie("oauth_state")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": appErr{
				Code:    http.StatusBadRequest,
				Message: err.Error(),
			},
		})
		return
	} else if cookie != state {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": appErr{
				Code:    http.StatusBadRequest,
				Message: "Invalid state provided",
			},
		})
		return
	}
	c.SetCookie("oauth_state", "", 1, "", "", false, true)
	token, err := oauthConfig[provider].Exchange(oauth2.NoContext, code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": appErr{
				Code:    http.StatusBadRequest,
				Message: err.Error(),
			},
		})
		return
	}
	client := oauthConfig[provider].Client(oauth2.NoContext, token)
	resp, err := client.Get(oauthAPI[provider])
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": appErr{
				Code:    http.StatusBadRequest,
				Message: err.Error(),
			},
		})
		return
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		glog.Errorf("[Gin-OAuth] Could not read Body: %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": appErr{
				Code:    http.StatusInternalServerError,
				Message: err.Error(),
			},
		})
		return
	}
	var user oauthUser
	err = json.Unmarshal(data, &user)
	if err != nil {
		glog.Errorf("[Gin-OAuth] Json decoded error: %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": appErr{
				Code:    http.StatusInternalServerError,
				Message: err.Error(),
			},
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": http.StatusOK,
		"user": user,
	})
}

func setup(redirectURL, credFile string, scopes []string, endpoint oauth2.Endpoint) *oauth2.Config {
	var c credential
	file, err := ioutil.ReadFile(credFile)
	if err != nil {
		log.Fatalf("[Gin-OAuth] File error: %v\n", err)
	}
	json.Unmarshal(file, &c)
	return &oauth2.Config{
		ClientID:     c.Client,
		ClientSecret: c.Secret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		Endpoint:     endpoint,
	}
}

func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
