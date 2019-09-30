//
// Copyright (c) Mainflux
//
// SPDX-License-Identifier: Apache-2.0
//

package sdk

import (
	"bytes"
	"encoding/json"
	"net/http"
)

func (sdk mfSDK) ConfigBootstrap(user User) error {
	data, err := json.Marshal(user)
	if err != nil {
		return ErrInvalidArgs
	}

	url := createURL(sdk.baseURL, sdk.usersPrefix, "users")

	resp, err := sdk.client.Post(url, string(CTJSON), bytes.NewReader(data))
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusCreated {
		switch resp.StatusCode {
		case http.StatusBadRequest:
			return ErrInvalidArgs
		case http.StatusConflict:
			return ErrConflict
		default:
			return ErrFailedCreation
		}
	}

	return nil
}
