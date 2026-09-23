package config

import (
	"log"

	"github.com/spf13/viper"
)

type Config struct {
	DatabaseURL string `mapstructure:"DATABASE_URL"`
	RedisURL    string `mapstructure:"REDIS_URL"`
	ProxyURL    string `mapstructure:"PROXY_URL"`
	ServerPort  int    `mapstructure:"SERVER_PORT"`
}

func LoadConfig() (*Config, error) {
	viper.SetConfigFile(".env")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		log.Println("No .env file found, relying on system environment variables.")
	}

	viper.BindEnv("DATABASE_URL")
	viper.BindEnv("REDIS_URL")
	viper.BindEnv("PROXY_URL")
	viper.BindEnv("SERVER_PORT")

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
