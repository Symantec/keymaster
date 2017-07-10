package main

import (
	"bytes"
	"encoding/gob"
	"io/ioutil"
	"log"
	"path/filepath"
)

const userProfileFilename = "userProfiles.gob"
const userProfilePrefix = "profile_"
const userProfileSuffix = ".gob"

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

func getFilenameForUser(state *RuntimeState, username string) string {
	return filepath.Join(state.Config.Base.DataDirectory, userProfilePrefix+username+userProfileSuffix)
}

/// Now we change the api to be load/save per user
func (state *RuntimeState) LoadUserProfile(username string) (*userProfile, error) {
	userProfilePath := getFilenameForUser(state, username)
	fileBytes, err := exitsAndCanRead(userProfilePath, "user Profile file")
	if err != nil {
		log.Printf("problem with user Profile data")
		return nil, nil
	}
	gobReader := bytes.NewReader(fileBytes)
	_ = gob.NewDecoder(gobReader)
	return nil, nil
}
