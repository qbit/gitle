package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/sosedoff/gitkit"
	"golang.org/x/crypto/ssh"
	"suah.dev/protect"
	"tailscale.com/tsnet"
)

func envOr(name string, def string) string {
	s := os.Getenv(name)
	if s == "" {
		return def
	}
	return s
}

var (
	akSrc   string
	faFPs   string
	hostKey string
	name    string
	port    string
	repos   string
	home    string
)

func init() {
	akSrc = envOr("GITLE_AUTH_KEYS", "/var/gitle/authorized_keys")
	faFPs = envOr("GITLE_FULL_ACCESS_FINGREPRINTS", "/var/gitle/full_access_fingerprints")
	hostKey = envOr("GITLE_HOST_KEY", "/var/gitle/host_key")
	name = envOr("GITLE_NAME", "gitle")
	port = envOr("GITLE_PORT", ":22")
	repos = envOr("GITLE_REPOS", "/var/gitle/repos")
	home = envOr("GITLE_HOME", "/var/gitle")

	os.Setenv("HOME", home)
}

func main() {

	protect.Unveil(home, "rwc")
	protect.Unveil(repos, "rwc")
	protect.Unveil(akSrc, "r")
	protect.Unveil(faFPs, "r")
	protect.Unveil(hostKey, "r")
	protect.Unveil("/dev", "r")
	protect.Unveil("/dev/null", "rw")
	protect.Unveil("/usr/local/bin/", "rx")
	protect.UnveilBlock()

	server := gitkit.NewSSH(gitkit.Config{
		Dir:        repos,
		AutoCreate: true,
	})

	tsServer := &tsnet.Server{
		Dir:      home,
		Hostname: name,
		AuthKey:  envOr("TS_AUTH_TOKEN", ""),
	}

	ln, err := tsServer.Listen("tcp", port)
	if err != nil {
		log.Fatal("can't listen: ", err)
	}

	fa, err := ioutil.ReadFile(faFPs)
	if err != nil {
		log.Fatalf("can't load full_access_fingreprints file: %s, err: %v", faFPs, err)
	}
	fpMap := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(fa))
	for scanner.Scan() {
		fp := scanner.Text()
		fpMap[fp] = true
	}

	akb, err := ioutil.ReadFile(akSrc)
	if err != nil {
		log.Fatalf("can't load authorized keys file: %s, err: %v", akSrc, err)
	}

	akMap := map[string]bool{}
	for len(akb) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(akb)
		if err != nil {
			log.Fatalf("failed to read pubKey entry: %v", err)
		}

		akMap[string(pubKey.Marshal())] = true
		akb = rest
	}

	b, err := ioutil.ReadFile(hostKey)
	if err != nil {
		log.Fatalf("failed to read %s: %v", hostKey, err)
	}
	pk, err := ssh.ParsePrivateKey(b)
	if err != nil {
		log.Fatalf("failed to parse %s: %v", hostKey, err)
	}

	sshConfig := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-gitle",
		PublicKeyCallback: func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if akMap[string(pubKey.Marshal())] {
				fp := ssh.FingerprintSHA256(pubKey)
				isRO := "yes"
				if fpMap[fp] {
					isRO = "no"
				}
				return &ssh.Permissions{
					Extensions: map[string]string{
						"pubkey-fp": fp,
						"key-id":    fp,
					},
					CriticalOptions: map[string]string{
						"is-ro": isRO,
					},
				}, nil
			}
			return nil, fmt.Errorf("unknown public key for %q", conn.User())
		},
	}

	sshConfig.AddHostKey(pk)
	server.SetSSHConfig(sshConfig)
	server.SetListener(ln)

	err = server.Serve()
	if err != nil {
		log.Fatalf("failed to listen: %v\n", err)
	}
}
