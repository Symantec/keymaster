package main

import (
	"bytes"
	"encoding/gob"
	"io/ioutil"
	"log"
	"os"
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

/// Adding api to be load/save per user
func getFilenameForUser(state *RuntimeState, username string) string {
	return filepath.Join(state.Config.Base.DataDirectory, userProfilePrefix+username+userProfileSuffix)
}

// If there a valid user profile returns: profile, true nil
// If there is NO user profile returns default_object, false, nil
// Any other case: nil, false, error
func (state *RuntimeState) LoadUserProfile(username string) (profile *userProfile, ok bool, err error) {
	var defaultProfile userProfile
	fileName := getFilenameForUser(state, username)

	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		return &defaultProfile, false, nil
	}

	fileBytes, err := exitsAndCanRead(fileName, "user Profile file")
	if err != nil {
		log.Printf("problem with user Profile data")
		return nil, false, err
	}
	gobReader := bytes.NewReader(fileBytes)
	decoder := gob.NewDecoder(gobReader)
	err = decoder.Decode(&defaultProfile)
	if err != nil {
		return nil, false, err
	}
	//log.Printf("loaded profile=%+v", defaultProfile)
	return &defaultProfile, true, nil
}

func (state *RuntimeState) SaveUserProfile(username string, profile *userProfile) error {
	var gobBuffer bytes.Buffer

	//log.Printf("saving profile=%+v", profile)

	encoder := gob.NewEncoder(&gobBuffer)
	if err := encoder.Encode(profile); err != nil {
		return err
	}
	fileName := getFilenameForUser(state, username)
	return ioutil.WriteFile(fileName, gobBuffer.Bytes(), 0640)
}
