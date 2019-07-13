package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/google/uuid"
	"github.com/ncw/rclone/lib/oauthutil"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jwt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
)

func main() {

	realArgs := os.Args[1:]

	if len(realArgs) >= 1 && realArgs[0] == "auth" {

		ClientID := "zp0jwu2l9ny9kxo2p9tyh5i1ojywqpzx"
		ClientSecret := "K00ILJutJjlegR5834wSYTpwjdiaay0i"

		oauthConfig := &oauth2.Config{
			Scopes: nil,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://account.box.com/api/oauth2/authorize",
				TokenURL: "https://api.box.com/oauth2/token",
			},
			ClientID:     ClientID,
			ClientSecret: ClientSecret,
			RedirectURL:  oauthutil.RedirectURL,
		}

		url := oauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
		fmt.Println("Visit the URL for the auth dialog: %v", url)

		var code string
		fmt.Printf("Authorization code: ")
		if _, err := fmt.Scan(&code); err != nil {
			fmt.Println(err)
		}

		// Use the custom HTTP client when requesting a token.
		httpClient := &http.Client{Timeout: 2 * time.Second}
		ctx := context.Background()
		ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

		tok, err := oauthConfig.Exchange(ctx, code)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(tok)
	}

	if len(realArgs) >= 1 && realArgs[0] == "jwt" {
		box_creds_file := "/home/zoran/_tmp/2019-07-11/box-python-sdk-test/216494880__config.json"

		type AppAuth struct {
			PublicKeyID string `json:"publicKeyID"`
			PrivateKey  string `json:"privateKey"`
			Passphrase  string `json:"passphrase"`
		}

		type BoxAppSettings struct {
			ClientID     string  `json:"clientID"`
			ClientSecret string  `json:"clientSecret"`
			AppAuth      AppAuth `json:"appAuth"`
		}

		type BoxJSONCreds struct {
			BoxAppSettings BoxAppSettings `json:"boxAppSettings"`
			EnterpriseID   string         `json:"enterpriseID"`
		}

		var boxJSONCreds BoxJSONCreds
		b, err := ioutil.ReadFile(box_creds_file)
		if err != nil {
			log.Fatalln(err)
		}

		err = json.Unmarshal(b, &boxJSONCreds)
		if err != nil {
			log.Fatalln(err)
		}

		pke, _ := pem.Decode([]byte(boxJSONCreds.BoxAppSettings.AppAuth.PrivateKey))
		if pke == nil {
			panic("failed to parse PEM block containing the private key")
		}

		pk, err := x509.DecryptPEMBlock(pke, []byte(boxJSONCreds.BoxAppSettings.AppAuth.Passphrase))
		if err != nil {
			panic("failed to decrypt the private key")
		}

		querystring := url.Values{
			"client_id":     []string{boxJSONCreds.BoxAppSettings.ClientID},
			"client_secret": []string{boxJSONCreds.BoxAppSettings.ClientSecret},
		}

		jwtConfig := &jwt.Config{
			Scopes: nil,

			// Email maps to `iss` claim
			// https://github.com/golang/oauth2/blob/master/jwt/jwt.go
			Email: boxJSONCreds.BoxAppSettings.ClientID,

			PrivateKey: pk,

			// PublicKeyId from the config
			PrivateKeyID: boxJSONCreds.BoxAppSettings.AppAuth.PublicKeyID,

			TokenURL: "https://api.box.com/oauth2/token",
			Audience: "https://api.box.com/oauth2/token",
			Expires:  60 * time.Second,

			// EnterpriseId
			Subject: boxJSONCreds.EnterpriseID,

			PrivateClaims: map[string]interface{}{
				"box_sub_type": "enterprise",
				"jti":          uuid.New(),
			},

			Querystring: querystring,

			UseIDToken: false,
		}

		// Use the custom HTTP client when requesting a token.
		httpClient := &http.Client{}
		ctx := context.Background()
		ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

		tokenSource := jwtConfig.TokenSource(ctx)
		access_token, err := tokenSource.Token()
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(access_token)
	}

	if len(realArgs) >= 1 && realArgs[0] == "test" {
		var access_token string
		fmt.Printf("Token: ")
		if _, err := fmt.Scan(&access_token); err != nil {
			fmt.Println(err)
		}

		// Test the token
		defaultClient := &http.Client{}
		req, err := http.NewRequest("GET", "https://api.box.com/2.0/users/me", nil)
		req.Header.Set("Authorization", "Bearer "+string(access_token))
		resp, err := defaultClient.Do(req)
		if err != nil {
			fmt.Println(err)
		}

		fmt.Printf("Response: %v\n", resp)
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Printf("Body: %v\n", string(bodyBytes))
	}
}
