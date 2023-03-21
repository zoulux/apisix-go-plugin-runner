/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package plugins

import (
	"encoding/json"
	pkgHTTP "github.com/apache/apisix-go-plugin-runner/pkg/http"
	"github.com/apache/apisix-go-plugin-runner/pkg/log"
	"github.com/apache/apisix-go-plugin-runner/pkg/plugin"
	"github.com/duke-git/lancet/v2/cryptor"
)

func init() {
	err := plugin.RegisterPlugin(new(ResponseEncrypt))
	if err != nil {
		log.Fatalf("failed to register plugin response-rewrite: %s", err)
	}
}

// ResponseEncrypt is a demo to show how to rewrite response data.
type ResponseEncrypt struct {
	// Embed the default plugin here,
	// so that we don't need to reimplement all the methods.
	plugin.DefaultPlugin
}

type ResponseEncryptConf struct {
	AesKey          string `json:"aes_key"`
	IgnoreHeaderKey string `json:"ignore_header_key"`
}

func (p *ResponseEncrypt) Name() string {
	return "response-encrypt"
}

func (p *ResponseEncrypt) ParseConf(in []byte) (interface{}, error) {
	conf := ResponseEncryptConf{}
	err := json.Unmarshal(in, &conf)
	if err != nil {
		return nil, err
	}

	return conf, nil
}

func (p *ResponseEncrypt) ResponseFilter(conf interface{}, w pkgHTTP.Response) {
	cfg := conf.(ResponseEncryptConf)
	if cfg.AesKey == "" {
		log.Errorf("response encrypt conf key is empty ")
		return
	}

	if w.StatusCode() != 200 {
		return
	}

	if w.Header().Get(cfg.IgnoreHeaderKey) != "" {
		return
	}

	bb, err := w.ReadBody()
	if err != nil {
		log.Errorf("failed to read response body: ", err)
		return
	}

	base64Data := cryptor.Base64StdEncode(string(cryptor.AesCbcEncrypt(bb, []byte(cfg.AesKey))))
	signSt := struct {
		Sign string `json:"sign"`
	}{
		Sign: base64Data,
	}
	newBody, _ := json.Marshal(signSt)
	w.Write(newBody)
}
