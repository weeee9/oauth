package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/weeee9/oauth/controllers"
)

func main() {
	router := gin.Default()
	router.LoadHTMLFiles("index.gohtml")
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.gohtml", nil)
	})
	router.GET("/oauth/:provider/login", controllers.OauthRedirect)
	router.GET("/oauth/:provider/callback", controllers.OauthCallback)
	router.Run() // run on port 8080
}
