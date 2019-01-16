// rds is a command that fetches AWS RDS credentials from AWS Secrets Manager
// and runs mysql command for those credentials.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	switch args[0] {
	case "-h", "-help", "--help":
		return errors.New(usage)
	}
	creds, err := credentials(args[0])
	if err != nil {
		return err
	}
	tf, err := ioutil.TempFile("", "wrap-")
	if err != nil {
		return err
	}
	defer tf.Close()
	os.Remove(tf.Name())
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "[client]\nhost=%s\n", creds.Host)
	fmt.Fprintf(buf, "user=%s\n", creds.User)
	fmt.Fprintf(buf, "password=%s\n", creds.Pass)
	if creds.Port > 0 {
		fmt.Fprintf(buf, "port=%d\n", creds.Port)
	}

	if _, err := tf.Write(buf.Bytes()); err != nil {
		return err
	}
	if _, err := tf.Seek(0, io.SeekStart); err != nil {
		return err
	}
	args[0] = "--defaults-extra-file=/proc/self/fd/3"
	cmd := exec.Command("mysql", args...)
	cmd.ExtraFiles = []*os.File{tf}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

type dbSpec struct {
	User string `json:"username"`
	Pass string `json:"password"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

func credentials(filter string) (*dbSpec, error) {
	sess, err := session.NewSession()
	if err != nil {
		return nil, err
	}
	var svc *secretsmanager.SecretsManager
	switch meta, err := ec2metadata.New(sess).GetInstanceIdentityDocument(); err {
	case nil:
		svc = secretsmanager.New(sess, aws.NewConfig().WithRegion(meta.Region))
	default:
		svc = secretsmanager.New(sess)
	}
	var secretsList []string
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = svc.ListSecretsPagesWithContext(ctx, &secretsmanager.ListSecretsInput{},
		func(page *secretsmanager.ListSecretsOutput, lastPage bool) bool {
			for _, entry := range page.SecretList {
				if !strings.Contains(*entry.Name, filter) {
					continue
				}
				secretsList = append(secretsList, *entry.Name)
			}
			return true
		})
	if err != nil {
		return nil, err
	}
	switch len(secretsList) {
	case 0:
		return nil, fmt.Errorf("no profile matching %q found", filter)
	case 1:
	default:
		return nil, fmt.Errorf("filter matched multiple profiles:\n\n\t%s", strings.Join(secretsList, "\n\t"))
	}
	res, err := svc.GetSecretValueWithContext(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretsList[0]),
	})
	if err != nil {
		return nil, err
	}
	creds := &dbSpec{}
	if err := json.Unmarshal([]byte(*res.SecretString), creds); err != nil {
		return nil, err
	}
	return creds, nil
}

const usage = `Usage: rds filter [mysql args]

where filter is a substring to match AWS Secrets Manager profile`
