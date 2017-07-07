package main

import (
	"bytes"
	"encoding/gob"
	"io/ioutil"
	"log"
	"path/filepath"
)

const userProfileFilename = "userProfiles.gob"

func (state *RuntimeState) SaveUserProfiles() error {
	var gobBuffer bytes.Buffer
	encoder := gob.NewEncoder(&gobBuffer)
	if err := encoder.Encode(state.userProfile); err != nil {
		return err
	}
	userProfilePath := filepath.Join(state.Config.Base.DataDirectory, userProfileFilename)
	return ioutil.WriteFile(userProfilePath, gobBuffer.Bytes(), 0640)
}

func (state *RuntimeState) LoadUserProfiles() error {
	userProfilePath := filepath.Join(state.Config.Base.DataDirectory, userProfileFilename)

	fileBytes, err := exitsAndCanRead(userProfilePath, "user Profile file")
	if err != nil {
		log.Printf("problem with user Profile data")
		return err
	}
	gobReader := bytes.NewReader(fileBytes)
	decoder := gob.NewDecoder(gobReader)
	return decoder.Decode(&state.userProfile)
}
