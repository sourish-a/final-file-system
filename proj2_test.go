package proj2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/cs161-staff/userlib"
	"github.com/google/uuid"
	_ "github.com/google/uuid"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

func TestIncorrectpassword(t *testing.T) {
	clear()
	t.Log("Incorrect Password test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "fubar")
	_, err2 := GetUser("alice", "fubar1")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	if err2 == nil {
		// t.Error says the test fails
		t.Error("Should have errored", err2)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Successfuly errored", err2)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

func TestCrypt(t *testing.T) {
	clear()
	t.Log("Encryption/Decryption test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	u2, err2 := GetUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	if err2 != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err2)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	t.Log("Retrieved user", u2)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}



func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var accessToken uuid.UUID

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	accessToken, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
}

func TestPUBLICSHARE(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test") //STORING FILE
	u.StoreFile("file1", v)

	var v2 []byte
	var accessToken uuid.UUID



	accessToken, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", accessToken) //SHARING FILE
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	userlib.DebugMsg("Loaded Data: %s\n", "hi")
	err = u2.AppendFile("file2", []byte(" this is an append"))
	if err != nil {
		t.Error("Unable to append to shared file")
		return
	}

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
}

func TestAppendFileBasic(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	v := []byte("This is a test. ") //STORING FILE
	u.StoreFile("file1", v)
	err = u.AppendFile("file1", []byte("Append 1. "))
	if err != nil {
		t.Error("Append1 failed: ", err)
	}
	err = u.AppendFile("file1", []byte("Append 2. "))
	if err != nil {
		t.Error("Append2 failed: ", err)
	}
	err = u.AppendFile("file1", []byte("Append 3. "))
	if err != nil {
		t.Error("Append3 failed: ", err)
	}
	err = u.AppendFile("file1", []byte("Append 4. "))
	if err != nil {
		t.Error("Append4 failed: ", err)
	}

	v2 := []byte("This is a test. Append 1. Append 2. Append 3. Append 4. ")
	u.StoreFile("file2", v2)

	file1_loaded, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download file 1.")
		return
	}
	file2_loaded, err := u.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download file 2.")
		return
	}
	if !reflect.DeepEqual(file1_loaded, file2_loaded) {
		t.Error("Appends did not work: ", file1_loaded, file2_loaded)
		return
	}
}

func TestShareThenAppend(t *testing.T) {
	clear()
	// initialize users
	alice, _ := InitUser("Alice", "ImSoPretty")
	bob, _ := InitUser("Bob", "MyNameIsBob")

	f := []byte("Test file for this testcase.")
	alice.StoreFile("file1", f)

	recUUID, _ := alice.ShareFile("file1", "Bob")
	bob.ReceiveFile("file1", "Alice", recUUID)

	alice_loaded_file, _ := alice.LoadFile("file1")
	bob_loaded_file, _ := bob.LoadFile("file1")
	if !reflect.DeepEqual(alice_loaded_file, bob_loaded_file) {
		t.Error("Bob's shared file is not the same: ", alice_loaded_file, bob_loaded_file)
		return
	}

	alice.AppendFile("file1", []byte("Append 1. "))

	alice_loaded_file, _ = alice.LoadFile("file1")
	bob_loaded_file, _ = bob.LoadFile("file1")
	if !reflect.DeepEqual(alice_loaded_file, bob_loaded_file) {
		t.Error("Bob's shared file is not the same after append: ", alice_loaded_file, bob_loaded_file)
		return
	}
	return
}


func TestShareAndReceiveAndRevokeBasic(t *testing.T) {
	clear()

	// initialize users
	alice, err := InitUser("Alice", "Fubar")
	if err != nil {
		t.Error("Failed to initialize Alice", err)
		return
	}
	bob, err2 := InitUser("Bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize Bob", err2)
		return
	}
	joe, err3 := InitUser("Joe", "foobar")
	if err3 != nil {
		t.Error("Failed to initialize Joe", err2)
		return
	}
	joesChild, err3 := InitUser("JoesChild", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize JoesChild", err2)
		return
	}
	bobsChild, err3 := InitUser("BobsChild", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize BobsChild", err2)
		return
	}

	// store file
	v := []byte("This is a test")
	alice.StoreFile("file1", v)

	// share and subsequently receive files
	alice_bob_uuid, err := alice.ShareFile("file1", "Bob")
	if err != nil {
		t.Error("Alice was unable to share the file with Bob: ", err)
	}
	err = bob.ReceiveFile("file1", "Alice", alice_bob_uuid)
	if err != nil {
		t.Error("Bob was unable to receive the file from Alice: ", err)
	}
	alice_joe_uuid, err := alice.ShareFile("file1", "Joe")
	if err != nil {
		t.Error("Alice was unable to share the file with Joe: ", err)
	}
	err = joe.ReceiveFile("file1", "Alice", alice_joe_uuid)
	if err != nil {
		t.Error("Joe was unable to receive the file from Alice: ", err)
	}
	joe_joesChild_uuid, err := joe.ShareFile("file1", "JoesChild")
	if err != nil {
		t.Error("Joe was unable to share the file with JoesChild: ", err)
	}
	err = joesChild.ReceiveFile("file1", "Joe", joe_joesChild_uuid)
	if err != nil {
		t.Error("JoesChild was unable to receive the file from Joe: ", err)
	}
	bob_bobsChild_uuid, err := bob.ShareFile("file1", "BobsChild")
	if err != nil {
		t.Error("Bob was unable to share the file with BobsChild: ", err)
	}
	err = bobsChild.ReceiveFile("file1", "Bob", bob_bobsChild_uuid)
	if err != nil {
		t.Error("BobsChild was unable to receive the file from Bob")
	}

	// ensure everybody has access and file loads properly
	alice_loaded_file, err := alice.LoadFile("file1")
	if err != nil {
		t.Error("Alice failed to download file 1.", err)
		return
	}
	joe_loaded_file, err := joe.LoadFile("file1")
	if err != nil {
		t.Error("Joe failed to download file 1.", err)
		return
	}
	bob_loaded_file, err := bob.LoadFile("file1")
	if err != nil {
		t.Error("Bob failed to download file 1.", err)
		return
	}
	joesChild_loaded_file, err := joesChild.LoadFile("file1")
	if err != nil {
		t.Error("JoesChild failed to download file 1.", err)
		return
	}
	bobsChild_loaded_file, err := bobsChild.LoadFile("file1")
	if err != nil {
		t.Error("BobsChild failed to download file 1.", err)
		return
	}

	// check equality of all the files
	if !reflect.DeepEqual(alice_loaded_file, joe_loaded_file) {
		t.Error("Joe's shared file is not the same: ", alice_loaded_file, joe_loaded_file)
		return
	}
	if !reflect.DeepEqual(alice_loaded_file, bob_loaded_file) {
		t.Error("Bob's shared file is not the same: ", alice_loaded_file, bob_loaded_file)
		return
	}
	if !reflect.DeepEqual(alice_loaded_file, joesChild_loaded_file) {
		t.Error("JoesChild's shared file is not the same: ", alice_loaded_file, joesChild_loaded_file)
		return
	}
	if !reflect.DeepEqual(alice_loaded_file, bobsChild_loaded_file) {
		t.Error("BobsChild's shared file is not the same: ", alice_loaded_file, bobsChild_loaded_file)
		return
	}

	// Revoke access from joe
	err = alice.RevokeFile("file1", "Joe")
	if err != nil {
		t.Error("Unable to revoke file from Joe: ", err)
	}
	bob_loaded_file, err = bob.LoadFile("file1")
	if err != nil {
		t.Error("Bob failed to download file 1 after revoke.", err)
		return
	}
	alice_loaded_file, err = alice.LoadFile("file1")
	if err != nil {
	t.Error("Alice failed to download file 1 after revoking. ", err)
	 	return
	}
	bobsChild_loaded_file, err = bobsChild.LoadFile("file1")
	if err != nil {
		t.Error("BobsChild failed to download file 1 after revoke.", err)
		return
	}
	joe_loaded_file, err = joe.LoadFile("file1")
	if err == nil {
		t.Error("Joe was able to download file 1 after revoke: ", err)
		return
	}
	joesChild_loaded_file, err = joesChild.LoadFile("file1")
	if err == nil {
		t.Error("JoesChild was able to download file 1 after revoke: ", err)
		return
	}
}

func TestRevokeThenReceive(t *testing.T) {
	clear()
	return
}
