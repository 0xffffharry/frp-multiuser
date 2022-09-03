package lib

import (
	"context"
	"encoding/json"
	"fmt"
	plugin "github.com/fatedier/frp/pkg/plugin/server"
	"github.com/fsnotify/fsnotify"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

type Config struct {
	BindAddress string
	AuthFile    string
	Inotify     bool
}

type Map struct {
	Data        map[string]string
	RefreshChan chan struct{}
	Lock        sync.RWMutex
}

func NewServer(cfg Config) {
	logger := log.Logger{}
	logger.SetFlags(log.LstdFlags | log.Lshortfile)
	logger.SetOutput(os.Stdout)
	logger.SetPrefix("")
	_, _, err := net.SplitHostPort(cfg.BindAddress)
	if err != nil {
		logger.Fatalf("parse bind address error: %v\n", err)
	}
	AuthMap, err := readAuthFile(cfg.AuthFile)
	if err != nil {
		logger.Fatalf("read auth file error: %v\n", err)
	}
	m := &Map{
		Data:        AuthMap,
		Lock:        sync.RWMutex{},
		RefreshChan: make(chan struct{}, 5),
	}
	wg := sync.WaitGroup{}
	ctx, ctxFunc := context.WithCancel(context.Background())
	defer ctxFunc()
	if cfg.Inotify {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := inotifyAuthFile(cfg.AuthFile, &m.RefreshChan, &ctx, &logger)
			if err != nil {
				ctxFunc()
				logger.Fatalf("inotify auth file error: %v\n", err)
				return
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-m.RefreshChan:
					AuthMap, err := readAuthFile(cfg.AuthFile)
					if err != nil {
						logger.Printf("read auth file error: %v\n", err)
						continue
					}
					m.Lock.Lock()
					m.Data = AuthMap
					m.Lock.Unlock()
				}
			}
		}()
	}
	server := http.Server{}
	server.Addr = cfg.BindAddress
	server.ErrorLog = nil
	server.Handler = http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Handler(w, r, m)
	}))
	logger.Println(fmt.Sprintf("listen on %s", cfg.BindAddress))
	_ = server.ListenAndServe()
	ctxFunc()
	wg.Wait()
}

func readAuthFile(filename string) (map[string]string, error) {
	AuthDataBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	AuthData := string(AuthDataBytes)
	AuthData = strings.TrimRight(AuthData, "\r")
	AuthMap := make(map[string]string)
	for _, row := range strings.Split(AuthData, "\n") {
		if strings.Contains(row, "=") {
			kvs := strings.SplitN(row, "=", 2)
			if strings.TrimSpace(kvs[1]) != "" {
				AuthMap[strings.TrimSpace(kvs[0])] = strings.TrimSpace(kvs[1])
			}
		}
	}
	return AuthMap, nil
}

func inotifyAuthFile(filename string, refreshChan *chan struct{}, ctx *context.Context, logger *log.Logger) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer w.Close()
	err = w.Add(filename)
	if err != nil {
		return err
	}
	for {
		select {
		case <-(*ctx).Done():
			return nil
		case event := <-w.Events:
			switch event.Op {
			case fsnotify.Write:
				logger.Println("auth file changed, read again...")
				*refreshChan <- struct{}{}
			default:
			}
		}
	}
}

func Handler(w http.ResponseWriter, r *http.Request, m *Map) {
	var pluginRequest plugin.Request
	var pluginLoginContent plugin.LoginContent
	pluginRequest.Content = &pluginLoginContent
	byteData, err := ioutil.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"msg": "%s"}`, err.Error())))
		return
	}
	err = json.Unmarshal(byteData, &pluginRequest)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"msg": "%s"}`, err.Error())))
		return
	}
	var pluginResponse plugin.Response
	user := pluginLoginContent.User
	password := pluginLoginContent.Metas["password"]
	if user == "" || password == "" {
		pluginResponse.Reject = true
		pluginResponse.RejectReason = "user or meta password can not be empty"
		resp, err := json.Marshal(pluginResponse)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(fmt.Sprintf(`{"msg": "%s"}`, err.Error())))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp)
		return
	}
	m.Lock.RLock()
	check := m.Data[user] == password
	m.Lock.RUnlock()
	if check {
		pluginResponse.Unchange = true
	} else {
		pluginResponse.Reject = true
		pluginResponse.RejectReason = fmt.Sprintf("user: `%s` invalid password", user)
	}
	resp, err := json.Marshal(pluginResponse)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(fmt.Sprintf(`{"msg": "%s"}`, err.Error())))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
	return
}
