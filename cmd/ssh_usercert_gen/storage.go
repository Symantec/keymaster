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

/// Adding api to be load/save per user
func getFilenameForUser(state *RuntimeState, username string) string {
	return filepath.Join(state.Config.Base.DataDirectory, userProfilePrefix+username+userProfileSuffix)
}

// Notice: each operation load/save should be atomic. For inital version we
// are using a RWMutex to al least serialize writes and allow for some
// read parallelism. Once SQL is implemented this RWMutex should be removed

// If there a valid user profile returns: profile, true nil
// If there is NO user profile returns default_object, false, nil
// Any other case: nil, false, error
func (state *RuntimeState) LoadUserProfile(username string) (profile *userProfile, ok bool, err error) {
	var defaultProfile userProfile
	fileName := getFilenameForUser(state, username)

	state.storageRWMutex.RLock()
	defer state.storageRWMutex.RUnlock()

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
	state.storageRWMutex.Lock()
	defer state.storageRWMutex.Unlock()
	return ioutil.WriteFile(fileName, gobBuffer.Bytes(), 0640)
}
