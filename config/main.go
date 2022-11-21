package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/olxbr/osm/osm-config-lambda/org"
)

func main() {
	lambda.Start(LambdaHandler)
}

func getEnv(key, fallback string) string {
    if value, ok := os.LookupEnv(key); ok {
        return value
    }
    return fallback
}

func apiGatewayResponse(i interface{}, code int) events.APIGatewayProxyResponse {
	response := events.APIGatewayProxyResponse{}
	j, _ := json.Marshal(i)
	response.Body = string(j)
	response.StatusCode = code
	return response
}

func LambdaHandler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
  	if err != nil {
		log.Fatal(err)
	}

	trustRoleName := getEnv("TRUST_ROLE_NAME", "org-osm-api")
	managementAccountRole := getEnv("MANAGEMENT_ACCOUNT_ROLE", "")
	supportedOUs := strings.Split(getEnv("SUPPORTED_OUS", ""), ",")
	roleProvider := org.NewAssumeRoleProvider(cfg, trustRoleName, managementAccountRole)
	accounts := roleProvider.ListAccountsForOUs(supportedOUs)

  	return apiGatewayResponse(accounts, 200), nil
}
