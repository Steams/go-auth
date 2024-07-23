package main

import (
	"fmt"
	"os"

	"github.com/spf13/viper"

	"local/auth/pkg/server"
	"local/auth/pkg/session"
	session_repo "local/auth/pkg/session/mock_repo"

	"local/auth/pkg/identity"
	identity_repo "local/auth/pkg/identity/mock_repo"
)

func main() {
	fmt.Println("Starting----")

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func run() error {
	viper.SetConfigName("auth")
	viper.SetConfigType("yaml")

	viper.AddConfigPath(".")
	err := viper.ReadInConfig()

	if err != nil {
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

	port := viper.GetString("port")
	// clean_db := viper.GetBool("clean_db")
	// db_location := viper.GetString("db")

	identityRepo := identity_repo.New(make(map[string]identity.User))
	sessionRepo := session_repo.New(make(map[string]string))
	identityService := identity.CreateService(identityRepo)
	sessionService := session.CreateService(sessionRepo)

	server := server.New(identityService, sessionService, port)

	if err = server.Run(); err != nil {
		return err
	}

	return nil
}
