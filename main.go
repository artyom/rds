// rds is a command that fetches AWS RDS credentials from AWS Secrets Manager
// and runs mysql command for those credentials.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

func main() {
	log.SetFlags(0)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	flag.Parse()
	if err := run(ctx, flag.Args()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("no filter provided")
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}
	creds, err := credentials(ctx, secretsmanager.NewFromConfig(cfg), args[0])
	if err != nil {
		return err
	}
	tf, err := os.CreateTemp("", "wrap-")
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
	go func() {
		<-ctx.Done()
		if cmd.Process != nil {
			cmd.Process.Signal(os.Interrupt)
		}
	}()
	return withMysqlInstallHint(cmd.Run())
}

type dbSpec struct {
	User string `json:"username"`
	Pass string `json:"password"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

func credentials(ctx context.Context, svc *secretsmanager.Client, filter string) (*dbSpec, error) {
	var secretsList []string
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	p := secretsmanager.NewListSecretsPaginator(svc, &secretsmanager.ListSecretsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, s := range page.SecretList {
			if s.Name == nil || !strings.Contains(*s.Name, filter) {
				continue
			}
			secretsList = append(secretsList, *s.Name)
		}
	}
	switch len(secretsList) {
	case 0:
		return nil, fmt.Errorf("no profile matching %q found", filter)
	case 1:
	default:
		return nil, fmt.Errorf("filter matched multiple profiles:\n\t%s", strings.Join(secretsList, "\n\t"))
	}
	res, err := svc.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &secretsList[0],
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

func init() {
	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), usage)
	}
}

func withMysqlInstallHint(werr error) error {
	if !errors.Is(werr, exec.ErrNotFound) {
		return werr
	}
	for _, cmd := range [...]string{"dnf", "yum", "apt"} {
		if _, err := exec.LookPath(cmd); err == nil {
			return fmt.Errorf("%w\ninstall mysql client with: %s install mysql", werr, cmd)
		}
	}
	return werr
}
