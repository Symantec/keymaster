package main

import (
	"bytes"
	"database/sql"
	"encoding/gob"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"os"
	"path/filepath"
)

const userProfilePrefix = "profile_"
const userProfileSuffix = ".gob"
const profileDBFilename = "userProfiles.sqlite3"

func initDB(state *RuntimeState) error {
	return initDBSQlite(state)
}

func initDBPostgres(state *RuntimeState) (err error) {
	state.db, err = sql.Open("postgres", state.Config.ProfileStorage.StorageUrl)
	if err != nil {
		return err
	}
	/// This should be changed to take care of DB schema
	if true {
		sqlStmt := `create table if not exists user_profile (id integer not null primary key, username text unique, profile_data bytea);`
		_, err = state.db.Exec(sqlStmt)
		if err != nil {
			log.Printf("%q: %s\n", err, sqlStmt)
			return err
		}
	}

	return nil
}

// This call initializes the database if it does not exist.
// TODO: update to handle multiple db types AND to perform auto-updates of the db.
func initDBSQlite(state *RuntimeState) (err error) {
	dbFilename := filepath.Join(state.Config.Base.DataDirectory, profileDBFilename)
	if _, err := os.Stat(dbFilename); os.IsNotExist(err) {
		//CREATE NEW DB
		state.db, err = sql.Open("sqlite3", dbFilename)
		if err != nil {
			return err
		}
		log.Printf("post DB open")
		// create profile table
		sqlStmt := `create table user_profile (id integer not null primary key, username text unique, profile_data blob);`
		_, err = state.db.Exec(sqlStmt)
		if err != nil {
			log.Printf("%q: %s\n", err, sqlStmt)
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
	stmt, err := state.db.Prepare("select profile_data from user_profile where username = ?")
	if err != nil {
		log.Fatal(err)
	}

	defer stmt.Close()
	var profileBytes []byte
	err = stmt.QueryRow(username).Scan(&profileBytes)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			log.Printf("err='%s'", err)
			return &defaultProfile, false, nil
		} else {
			log.Printf("Problem with db ='%s'", err)
			return nil, false, err
		}

	}
	//log.Printf("bytes len=%d", len(profileBytes))
	//gobReader := bytes.NewReader(fileBytes)
	gobReader := bytes.NewReader(profileBytes)
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

	encoder := gob.NewEncoder(&gobBuffer)
	if err := encoder.Encode(profile); err != nil {
		return err
	}

	//insert into DB
	tx, err := state.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare("insert or replace into user_profile(username, profile_data) values(?, ?)")
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
