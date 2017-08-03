package main

import (
	"bytes"
	"database/sql"
	"encoding/gob"
	"errors"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"os"
	"path/filepath"
	"strings"
)

const userProfilePrefix = "profile_"
const userProfileSuffix = ".gob"
const profileDBFilename = "userProfiles.sqlite3"

func initDB(state *RuntimeState) error {
	if *debug {
		logger.Printf("storage=%s", state.Config.ProfileStorage.StorageUrl)
	}
	storageURL := state.Config.ProfileStorage.StorageUrl
	if storageURL == "" {
		storageURL = "sqlite:"
	}
	splitString := strings.SplitN(storageURL, ":", 2)
	if len(splitString) < 1 {
		logger.Printf("invalid string")
		err := errors.New("Bad storage url string")
		return err
	}
	switch splitString[0] {
	case "sqlite":
		logger.Printf("doing sqlite")
		return initDBSQlite(state)
	case "postgresql":
		logger.Printf("doing postgres")
		return initDBPostgres(state)
	default:
		logger.Printf("invalid storage url string")
		err := errors.New("Bad storage url string")
		return err
	}

	err := errors.New("invalid state")
	return err

}

func initDBPostgres(state *RuntimeState) (err error) {
	state.dbType = "postgres"
	state.db, err = sql.Open("postgres", state.Config.ProfileStorage.StorageUrl)
	if err != nil {
		return err
	}
	/// This should be changed to take care of DB schema
	if true {
		sqlStmt := `create table if not exists user_profile (id serial not null primary key, username text unique, profile_data bytea);`
		_, err = state.db.Exec(sqlStmt)
		if err != nil {
			logger.Printf("%q: %s\n", err, sqlStmt)
			return err
		}
	}

	return nil
}

// This call initializes the database if it does not exist.
// TODO: update to handle multiple db types AND to perform auto-updates of the db.
func initDBSQlite(state *RuntimeState) (err error) {
	state.dbType = "sqlite"
	dbFilename := filepath.Join(state.Config.Base.DataDirectory, profileDBFilename)
	if _, err := os.Stat(dbFilename); os.IsNotExist(err) {
		//CREATE NEW DB
		state.db, err = sql.Open("sqlite3", dbFilename)
		if err != nil {
			return err
		}
		logger.Printf("post DB open")
		// create profile table
		sqlStmt := `create table user_profile (id integer not null primary key, username text unique, profile_data blob);`
		_, err = state.db.Exec(sqlStmt)
		if err != nil {
			logger.Printf("%q: %s\n", err, sqlStmt)
			return err
		}

		return nil
	}

	// try open the DB
	if state.db == nil {

		state.db, err = sql.Open("sqlite3", dbFilename)
		if err != nil {
			return err
		}
		//defer state.db.Close()
	}
	return nil
}

var loadUserProfileStmt = map[string]string{
	"sqlite":   "select profile_data from user_profile where username = ?",
	"postgres": "select profile_data from user_profile where username = $1",
}

/// Adding api to be load/save per user

// Notice: each operation load/save should be atomic. For inital version we
// are using a RWMutex to al least serialize writes and allow for some
// read parallelism. Once SQL is implemented this RWMutex should be removed

// If there a valid user profile returns: profile, true nil
// If there is NO user profile returns default_object, false, nil
// Any other case: nil, false, error
func (state *RuntimeState) LoadUserProfile(username string) (profile *userProfile, ok bool, err error) {
	var defaultProfile userProfile
	defaultProfile.U2fAuthData = make(map[int64]*u2fAuthData)
	//load from DB
	stmtText := loadUserProfileStmt[state.dbType]
	stmt, err := state.db.Prepare(stmtText)
	if err != nil {
		logger.Print("Error Preparing statement")
		logger.Fatal(err)
	}

	defer stmt.Close()
	var profileBytes []byte
	err = stmt.QueryRow(username).Scan(&profileBytes)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			logger.Printf("err='%s'", err)
			return &defaultProfile, false, nil
		} else {
			logger.Printf("Problem with db ='%s'", err)
			return nil, false, err
		}

	}
	//logger.Printf("bytes len=%d", len(profileBytes))
	//gobReader := bytes.NewReader(fileBytes)
	gobReader := bytes.NewReader(profileBytes)
	decoder := gob.NewDecoder(gobReader)
	err = decoder.Decode(&defaultProfile)
	if err != nil {
		return nil, false, err
	}
	//logger.Printf("loaded profile=%+v", defaultProfile)
	return &defaultProfile, true, nil
}

var saveUserProfileStmt = map[string]string{
	"sqlite":   "insert or replace into user_profile(username, profile_data) values(?, ?)",
	"postgres": "insert into user_profile(username, profile_data) values ($1,$2) on CONFLICT(username) DO UPDATE set  profile_data = excluded.profile_data",
}

func (state *RuntimeState) SaveUserProfile(username string, profile *userProfile) error {
	var gobBuffer bytes.Buffer

	encoder := gob.NewEncoder(&gobBuffer)
	if err := encoder.Encode(profile); err != nil {
		return err
	}

	//insert into DB
	tx, err := state.db.Begin()
	if err != nil {
		return err
	}
	stmtText := saveUserProfileStmt[state.dbType]
	stmt, err := tx.Prepare(stmtText)
	if err != nil {
		return err
	}
	defer stmt.Close()
	_, err = stmt.Exec(username, gobBuffer.Bytes())
	if err != nil {
		return err
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}
