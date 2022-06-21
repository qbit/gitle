package main

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"os"
	"suah.dev/protect"

	"github.com/sosedoff/gitkit"
)

func envOr(name string, def string) string {
	s := os.Getenv(name)
	if s == "" {
		return def
	}
	return s
}

func main() {
	repos := envOr("GITLE_REPOS", "/var/gitle/repos")
	akSrc := envOr("GITLE_AUTH_KEYS", "var/gitle/authorized_keys")
	hostKey := envOr("GITLE_HOST_KEY", "/var/gitle/host_key")

	protect.Unveil(repos, "rwc")
	protect.Unveil(akSrc, "r")
	protect.Unveil(hostKey, "r")
	protect.Unveil("/dev", "r")
	protect.Unveil("/dev/null", "rw")
	protect.Unveil("/usr/local/bin/", "rx")
	protect.UnveilBlock()

	server := gitkit.NewSSH(gitkit.Config{
		Dir:        repos,
		AutoCreate: true,
	})

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

	server.SSHConfig = &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-gitle",
		PublicKeyCallback: func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if akMap[string(pubKey.Marshal())] {
				return &ssh.Permissions{
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubKey),
					},
				}, nil
			}
			return nil, fmt.Errorf("unknown public key for %q", conn.User())
		},
	}
	server.SSHConfig.AddHostKey(pk)
	server.SetupDone = true

	err = server.ListenAndServe(":2222")
	if err != nil {
		log.Fatalf("failed to listen: %v\n", err)
	}
}
