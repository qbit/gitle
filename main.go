package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"golang.org/x/crypto/ssh"

	"suah.dev/gitkit"
	"suah.dev/protect"
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
	akSrc := envOr("GITLE_AUTH_KEYS", "/var/gitle/authorized_keys")
	hostKey := envOr("GITLE_HOST_KEY", "/var/gitle/host_key")
	faFPs := envOr("GITLE_FULL_ACCESS_FINGREPRINTS", "/var/gitle/full_access_fingreprints")
	port := envOr("GITLE_PORT", ":2222")

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

	server.SSHConfig = &ssh.ServerConfig{
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
	server.SSHConfig.AddHostKey(pk)
	server.SetupDone = true

	err = server.ListenAndServe(port)
	if err != nil {
		log.Fatalf("failed to listen: %v\n", err)
	}
}
