package main

import (
	"flag"
	"frp-multiuser/lib"
	"net"
)

func main() {
	BindAddress := flag.String("addr", net.JoinHostPort("::", "7003"), "bind address")
	AuthFile := flag.String("auth_file", "./tokens", "auth token file")
	Inotify := flag.Bool("inotify", false, "use inotify to watch auth file")
	flag.Parse()
	lib.NewServer(lib.Config{
		BindAddress: *BindAddress,
		AuthFile:    *AuthFile,
		Inotify:     *Inotify,
	})
}
