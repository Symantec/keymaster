package main

import (
	"bytes"
	"database/sql"
	"encoding/gob"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

const userProfilePrefix = "profile_"
const userProfileSuffix = ".gob"
const profileDBFilename = "userProfiles.sqlite3"
const cachedDBFilename = "cachedDB.sqlite3"

func initDB(state *RuntimeState) (err error) {
	logger.Debugf(3, "Top of initDB")
	//open/create cache DB first
	cacheDBFilename := filepath.Join(state.Config.Base.DataDirectory, cachedDBFilename)
	state.cacheDB, err = initFileDBSQLite(cacheDBFilename, state.cacheDB)
	if err != nil {
		logger.Printf("Failure on creation of cacheDB")
		return err
	}

	logger.Debugf(3, "storage=%s", state.Config.ProfileStorage.StorageUrl)
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
	state.remoteDBQueryTimeout = time.Second * 2
	initialSleep := time.Second * 3
	go state.BackgroundDBCopy(initialSleep)
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

	err = errors.New("invalid state")
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
func initDBSQlite(state *RuntimeState) (err error) {
	state.dbType = "sqlite"
	dbFilename := filepath.Join(state.Config.Base.DataDirectory, profileDBFilename)
	state.db, err = initFileDBSQLite(dbFilename, state.db)
	return err
}

// This call initializes the database if it does not exist.
// TODO: update  to perform auto-updates of the db.
func initFileDBSQLite(dbFilename string, currentDB *sql.DB) (*sql.DB, error) {
	//state.dbType = "sqlite"
	//dbFilename := filepath.Join(state.Config.Base.DataDirectory, profileDBFilename)
	if _, err := os.Stat(dbFilename); os.IsNotExist(err) {
		//CREATE NEW DB
		fileDB, err := sql.Open("sqlite3", dbFilename)
		if err != nil {
			logger.Printf("Failure creating new db: %s", dbFilename)
			return nil, err
		}
		logger.Printf("post DB open")
		// create profile table
		sqlStmt := `create table user_profile (id integer not null primary key, username text unique, profile_data blob);`
		_, err = fileDB.Exec(sqlStmt)
		if err != nil {
			logger.Printf("%q: %s\n", err, sqlStmt)
			return nil, err
		}

		return fileDB, nil
	}

	// try open the DB
	if currentDB == nil {

		fileDB, err := sql.Open("sqlite3", dbFilename)
		if err != nil {
			return nil, err
		}
		return fileDB, nil
	}
	return currentDB, nil
}

func (state *RuntimeState) BackgroundDBCopy(initialSleep time.Duration) {
	time.Sleep(initialSleep)
	for {
		logger.Printf("starting db copy")
		err := copyDBIntoSQLite(state.db, state.cacheDB, "sqlite")
		if err != nil {
			logger.Printf("err='%s'", err)
		} else {
			logger.Printf("db copy success")
		}
		time.Sleep(time.Second * 300)
	}

}

func copyDBIntoSQLite(source, destination *sql.DB, destinationType string) error {
	if source == nil || destination == nil {
		err := errors.New("nil databases")
		return err
	}
	rows, err := source.Query("SELECT username,profile_data FROM user_profile")
	if err != nil {
		logger.Printf("err='%s'", err)
		return err
	}
	defer rows.Close()

	tx, err := destination.Begin()
	if err != nil {
		logger.Printf("err='%s'", err)
		return err
	}
	stmtText := saveUserProfileStmt[destinationType]
	stmt, err := tx.Prepare(stmtText)
	if err != nil {
		logger.Printf("err='%s'", err)
		return err
	}
	defer stmt.Close()

	for rows.Next() {
		var (
			username     string
			profileBytes []byte
		)
		if err := rows.Scan(&username, &profileBytes); err != nil {
			//log.Fatal(err)
			logger.Printf("err='%s'", err)
			return err
		}
		_, err = stmt.Exec(username, profileBytes)
		if err != nil {
			logger.Printf("err='%s'", err)
			return err
		}
		//fmt.Printf("%s is %d\n", name, age)
	}
	if err := rows.Err(); err != nil {
		//log.Fatal(err)
		logger.Printf("err='%s'", err)
		return err
	}
	err = tx.Commit()
	if err != nil {
		logger.Printf("err='%s'", err)
		return err
	}
	return nil
}

var getUsersStmt = map[string]string{
	"sqlite":   "select username from user_profile order by username",
	"postgres": "select username from user_profile order by username",
}

type getUsersData struct {
	Names []string
	Err   error
}

func gatherUsers(stmt *sql.Stmt) ([]string, error) {
	rows, err := stmt.Query()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return names, nil
}

func (state *RuntimeState) GetUsers() ([]string, bool, error) {
	ch := make(chan getUsersData, 1)
	start := time.Now()
	go func() {
		stmtText := getUsersStmt[state.dbType]
		stmt, err := state.db.Prepare(stmtText)
		if err != nil {
			logger.Print("Error Preparing getUsers statement")
			logger.Fatal(err)
		}
		defer stmt.Close()
		if state.remoteDBQueryTimeout == 0 {
			time.Sleep(10 * time.Millisecond)
		}
		names, dbErr := gatherUsers(stmt)
		ch <- getUsersData{Names: names, Err: dbErr}
		close(ch)
	}()
	select {
	case dbMessage := <-ch:
		if dbMessage.Err != nil {
			logger.Printf("Problem with db ='%s'", dbMessage.Err)
		} else {
			metricLogExternalServiceDuration("storage-read", time.Since(start))
		}
		return dbMessage.Names, false, dbMessage.Err
	case <-time.After(state.remoteDBQueryTimeout):
		logger.Printf("GOT a timeout")
		stmtText := getUsersStmt["sqlite"]
		stmt, err := state.cacheDB.Prepare(stmtText)
		if err != nil {
			logger.Print("Error Preparing statement")
			logger.Fatal(err)
		}
		defer stmt.Close()
		names, dbErr := gatherUsers(stmt)
		if dbErr != nil {
			logger.Printf("Problem with db = '%s'", err)
		} else {
			logger.Println("GOT data from db cache")
		}
		return names, true, dbErr
	}
}

var loadUserProfileStmt = map[string]string{
	"sqlite":   "select profile_data from user_profile where username = ?",
	"postgres": "select profile_data from user_profile where username = $1",
}

/// Adding api to be load/save per user

// Notice: each operation load/save should be atomic.

type loadUserProfileData struct {
	//fromDB       bool
	ProfileBytes []byte
	Err          error
}

// If there a valid user profile returns: profile, true nil
// If there is NO user profile returns default_object, false, nil
// Any other case: nil, false, error
func (state *RuntimeState) LoadUserProfile(username string) (profile *userProfile, ok bool, fromCache bool, err error) {
	var defaultProfile userProfile
	defaultProfile.U2fAuthData = make(map[int64]*u2fAuthData)

	ch := make(chan loadUserProfileData, 1)
	start := time.Now()
	go func(username string) { //loads profile from DB
		var profileMessage loadUserProfileData

		stmtText := loadUserProfileStmt[state.dbType]
		stmt, err := state.db.Prepare(stmtText)
		if err != nil {
			logger.Print("Error Preparing statement")
			logger.Fatal(err)
		}

		defer stmt.Close()
		// if the remoteDBQueryTimeout == 0 this means we are actuallty trying
		// to force the cached db. In single core systems, we need to ensure this
		// goroutine yields to sthis sleep is necesary
		if state.remoteDBQueryTimeout == 0 {
			time.Sleep(10 * time.Millisecond)
		}
		profileMessage.Err = stmt.QueryRow(username).Scan(&profileMessage.ProfileBytes)
		ch <- profileMessage
	}(username)
	var profileBytes []byte
	fromCache = false
	select {
	case dbMessage := <-ch:
		err = dbMessage.Err
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				logger.Printf("err='%s'", err)
				return &defaultProfile, false, fromCache, nil
			} else {
				logger.Printf("Problem with db ='%s'", err)
				return nil, false, fromCache, err
			}

		}
		metricLogExternalServiceDuration("storage-read", time.Since(start))
		profileBytes = dbMessage.ProfileBytes
	case <-time.After(state.remoteDBQueryTimeout):
		logger.Printf("GOT a timeout")
		fromCache = true
		// load from cache
		stmtText := loadUserProfileStmt["sqlite"]
		stmt, err := state.cacheDB.Prepare(stmtText)
		if err != nil {
			logger.Print("Error Preparing statement")
			logger.Fatal(err)
		}

		defer stmt.Close()
		err = stmt.QueryRow(username).Scan(&profileBytes)
		if err != nil {
			if err.Error() == "sql: no rows in result set" {
				logger.Printf("err='%s'", err)
				return &defaultProfile, false, true, nil
			} else {
				logger.Printf("Problem with db ='%s'", err)
				return nil, false, true, err
			}

		}
		logger.Printf("GOT data from db cache")

	}
	logger.Debugf(10, "profile bytes len=%d", len(profileBytes))
	//gobReader := bytes.NewReader(fileBytes)
	gobReader := bytes.NewReader(profileBytes)
	decoder := gob.NewDecoder(gobReader)
	err = decoder.Decode(&defaultProfile)
	if err != nil {
		return nil, false, fromCache, err
	}
	logger.Debugf(1, "loaded profile=%+v", defaultProfile)
	return &defaultProfile, true, fromCache, nil
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

	start := time.Now()
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
	metricLogExternalServiceDuration("storage-save", time.Since(start))
	return nil
}
