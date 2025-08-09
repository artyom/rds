// rds is a command that fetches AWS RDS credentials from AWS Secrets Manager
// and runs mysql command for those credentials.
package main

import (
	"bufio"
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
	"path/filepath"
	"strings"
	"sync"
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
	if dbname := defaultSchema(creds.profile); dbname != "" {
		fmt.Fprintf(buf, "database=%s\n", dbname)
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
	return withMysqlInstallHint(cmd.Run())
}

type dbSpec struct {
	profile string
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
		creds := &dbSpec{profile: filter}
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
	creds := &dbSpec{profile: secretsList[0]}
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
		if s := dbNamesFile(); s != "" {
			fmt.Fprintf(flag.CommandLine.Output(), "\nDefine default databases as `entry_name = database_name`, one per line,\nin %q\n", s)
		}
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

func defaultSchema(profile string) string {
	fname := dbNamesFile()
	if fname == "" {
		return ""
	}
	f, err := os.Open(fname)
	if err != nil {
		return ""
	}
	defer f.Close()
	for sc := bufio.NewScanner(f); sc.Scan(); {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != profile {
			continue
		}
		value = strings.TrimSpace(value)
		for _, r := range value {
			switch {
			case '0' <= r && r <= '9':
			case 'A' <= r && r <= 'Z':
			case 'a' <= r && r <= 'z':
			case r == '_':
			default:
				return ""
			}
		}
		return value
	}
	return ""
}

var dbNamesFile = sync.OnceValue(func() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "rds", "default-databases.txt")
})
