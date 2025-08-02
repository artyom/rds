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
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

func main() {
	log.SetFlags(0)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	direct := flag.Bool("d", false, "use cluster primary endpoint, can be used to bypass RDS proxy")
	flag.Parse()
	if err := run(ctx, *direct, flag.Args()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, direct bool, args []string) error {
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
	if direct {
		if creds.Host, creds.Port, err = clusterHostPort(ctx, rds.NewFromConfig(cfg), creds.Cluster); err != nil {
			return err
		}
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
	cmd := exec.CommandContext(ctx, "mysql", args...)
	cmd.ExtraFiles = []*os.File{tf}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.SysProcAttr = &syscall.SysProcAttr{Foreground: true}
	return withMysqlInstallHint(cmd.Run())
}

type dbSpec struct {
	User    string `json:"username"`
	Pass    string `json:"password"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Cluster string `json:"dbClusterIdentifier"`
}

func credentials(ctx context.Context, svc *secretsmanager.Client, filter string) (*dbSpec, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// when filter is an exact match of the secret name
	if res, err := svc.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: &filter}); err == nil {
		creds := &dbSpec{}
		if err := json.Unmarshal([]byte(*res.SecretString), creds); err != nil {
			return nil, err
		}
		return creds, nil
	}
	var secretsList []string
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

const usage = `Usage: rds [flags] filter [mysql args]

where filter is a substring to match AWS Secrets Manager profile

Flags:`

func init() {
	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), usage)
		flag.PrintDefaults()
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

func clusterHostPort(ctx context.Context, svc *rds.Client, clusterID string) (host string, port int, err error) {
	res, err := svc.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{DBClusterIdentifier: &clusterID})
	if err != nil {
		return "", 0, err
	}
	if l := len(res.DBClusters); l != 1 {
		return "", 0, fmt.Errorf("DescribeDBClusters (%s) returned %d results instead of 1", clusterID, l)
	}
	return *res.DBClusters[0].Endpoint, int(*res.DBClusters[0].Port), nil
}
