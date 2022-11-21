package org

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type AssumeRoleProvider struct {
	cfg                   aws.Config
	cli                   *sts.Client
	roleName              string
	managementAccountRole string
}

func NewAssumeRoleProvider(cfg aws.Config, role, mRole string) *AssumeRoleProvider {
	return &AssumeRoleProvider{
		cfg:                   cfg,
		cli:                   sts.NewFromConfig(cfg),
		roleName:              role,
		managementAccountRole: mRole,
	}
}

func (p *AssumeRoleProvider) AssumeRoleForAccount(account, region string) aws.Config {
	roleName := fmt.Sprintf("arn:aws:iam::%s:role/%s", account, p.roleName)
	return p.AssumeRole(roleName, region)
}

func (p *AssumeRoleProvider) AssumeRole(roleName, region string) aws.Config {
	nCfg := p.cfg.Copy()
	if region != "" {
		nCfg.Region = region
	}
	appCreds := stscreds.NewAssumeRoleProvider(p.cli, roleName)
	nCfg.Credentials = aws.NewCredentialsCache(appCreds)
	return nCfg
}

type Account struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (p *AssumeRoleProvider) ListAccountsForOUs(ous []string) []Account {
	accounts := []Account{}
	cfg := p.AssumeRole(p.managementAccountRole, os.Getenv("DEFAULT_REGION"))
	ctx := context.Background()
	cli := organizations.NewFromConfig(cfg)
	for _, ou := range ous {
		paginator := organizations.NewListChildrenPaginator(cli, &organizations.ListChildrenInput{
			ParentId:  aws.String(ou),
			ChildType: types.ChildTypeAccount,
		})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				log.Printf("Error getting accounts for OU %s: %s", ou, err)
				goto br
			}
			for _, a := range page.Children {
				if a.Type != types.ChildTypeAccount {
					continue
				}
				ao, err := cli.DescribeAccount(ctx, &organizations.DescribeAccountInput{
					AccountId: a.Id,
				})
				if err != nil {
					log.Printf("Error getting account info %s: %s", aws.ToString(a.Id), err)
					continue
				}
				accounts = append(accounts, Account{
					ID:   aws.ToString(a.Id),
					Name: aws.ToString(ao.Account.Name),
				})
			}
		}
	br:
	}
	return accounts
}
