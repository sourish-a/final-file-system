package proj2

// CS 161 Project 2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	"github.com/cs161-staff/userlib"

	// The JSON library will be useful for serializing go structs.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/json.html.
	"encoding/json"

	// Likewise, useful for debugging, etc.
	"encoding/hex"

	// The Datastore requires UUIDs to store key-value entries.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/uuid.html.
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// User is the structure definition for a user record.
type User struct {
	Username string
	Masterkey []byte
	Privdsk DSSignKey
	PrivRSA PKEDecKey
	Namespace map[string]FileFrame //maps hash of filename to UUID of where File struct exists

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type FileFrame struct {
	IsOwner bool
	FileUUID uuid.UUID //set to 0 unless owner, points to File struct
	SymmKey []byte // set to 0 unless owner
	SharedUsers map[string]string //maps username to acccess tokens for all shared users; exclusive to owner
	SharedFrame uuid.UUID //points to SharedFileFrame, only for shared users
	AccessToken []byte // set to 0 if owner, otherwise the key used to decrypt SharedFileFrame 
}

type File struct {
	FileUUID uuid.UUID
	Owner string


}

//intermediate struct between FileFrame and File, exclusive to non-owners
type SharedFileFrame struct { // will be encryped and MAC'd by access token for user
	SymmKey []byte //decrypt/encrypt key for FIle struct, changed when access is revoked to other user
	SharedFileUUID uuid.UUID //UUID that points to the File struct, changed when access is revoked to other user
	Revoked bool //true if their file access is revoked
}

type Invite struct {
	SharedFileUUID uuid.UUID //UUID of the SharedFileFrame
	Accessor []byte //encryption/decryption key to decrypt SharedFileFrame
}


// InitUser will be called a single time to initialize a new user.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	//TODO: This is a toy implementation.
	getuser, userExists := userlib.DatastoreGet(uuid.FromBytes(Hash(username)))
	if userExists == true {
		panic("User already exists")
		return nil, "User already exists"
	}
	userdata.Username = username
	userdata.Masterkey = Argon2Key(password, Hash(username), 16)
	userdata.PrivRSA, pubRSA := PKEKeyGen()
	userdata.Privdsk, pubDSK := DSKeyGen()
	toJson, _ := json.Marshal(userdata)
	iv := RandomBytes(16)
	jsonEnc := SymEnc(userdata.Masterkey, iv, toJson)
	userUUID := uuid.FromBytes(Hash(username))
	userlib.KeystoreSet("RSA" + username , pubRSA)
	userlib.KeystoreSet("DSK" + username , pubDSK)
	signature := DSSign(userdata.Privdsk, jsonEnc)
	userlib.DatastoreSet(userUUID, jsonEnc + signature)
	Namespace = make(map[string]FileFrame)
	//should also MAC this using Masterkey
	userlib.DatastoreSet()
	//End of toy implementation

	return &userdata, nil
}

// GetUser is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/getuser.html
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	userUUID := uuid.FromBytes(Hash(username))
	retrieved, exists := userlib.DatastoreGet(userUUID)
	if exists != true {
		panic("username does not exist")
		return nil, "username does not exist"
	}
	signature := retrieved[len(encJson) - 256:]
	encJson := retrieved[:len(encJson) - 256]
	pubRSA := KeystoreGet("RSA" + username)
	if DSVerify(pubRSA, encJson, signature) {
		panic("Data has been tampered with!!")
		return nil, "Data has been tampered with!"
	}
	master := Argon2Key(password, Hash(username), 16)
	unEncJson := SymDec(master, encJson)
	errorExists := json.Unmarshal(unEncJson, userdataptr)
	if errorExists {
		panic("incorrect password")
		return nil, "incorrect password"
	}
	return userdataptr, nil
}

// StoreFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/storefile.html
func (userdata *User) StoreFile(filename string, data []byte) (err error) {

	//TODO: This is a toy implementation.
	storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	jsonData, _ := json.Marshal(data)
	userlib.DatastoreSet(storageKey, jsonData)
	//End of toy implementation

	// Load the namespace map from the datastore using UUID
	// If the filename exists in the namespace:
	// 		Load the FileFrame Struct
	//		If I'm the owner, load the key and FileUUID from the FileFrameStruct directly
	// 		Otherwise load the SharedFileFrame from the DataStore and get the key and FileUUID from there
	// 		Load FileStruct from Datastore using FileUUID, unencrypt and ensure validity
	//		Change appends to 1
	//		Create new AppendNode and set the data to filedata and set next to null
	// 		create a new UUID and set firstAppend and lastAppend to this new UUID
	// 		encrypt the appendNode with HKDF(key, 1) and store it in the datastore at the new UUID
	//		encrypt and MAC the FileStruct and resave at same UUID
	//		
	// If the filename does not exist in the namespace:
	// 		Create a FileFrame Struct for that hashed filename, 
	//		Set the owner value to true, generate UUID for file, generate encryp/decryp key (HKDF(owners master, 16 random bytes)), create map of shared users to access tokens
	// 		Create a new FileStruct, set appends to 1
	//		Generate an AppendNodeUUID and set firstAppend and lastAppend to that UUID
	//		Create an AppendNode, set the filedata to data, set nextNode to Null
	//		Encrypt + Mac and save AppendNode at the new AppendNodeUUID
	// 		Update the owner of the new file to myself
	//		Encrypt + Mac and save FileStruct at new FileStructUUID

	hashedFilename := Hash(filename)
	userdata.

	return
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return

	// from the namespace map, use the hash(filename) as the key to get the FileFrameStruct
	// if NOT the owner:
	// 		load the SharedFileFrame from the datastore using the SharedFrame UUID in the FileFrameStruct
	// 		get encryp/decryption key and FileUUID from the SharedFileFrame struct
	// if owner:
	//		load the key and FileUUID from the FileFrameStruct directly
	// load the FileStruct from the DataStore using the FileUUID
	// unencrypt the FileStruct using the key and check HMAC for validity
	// if HMAC is invalid -- Error: file has been tampered with
	// else if data cannot be unmarshalled -- Error: user no longer has access, remove filename from namespace
	// Generate a new random UUID called newNode
	// Load AppendNode from LastAppendUUID (from the Datastore) and unencrypt it by HKDF(Symmkey, appends) and check MAC
	// Set nextAppendNode to this new UUID
	// Reencrypt and MAC using HKDF(symmkey, appends), put back in datastore at LastAppendUUID
	// Change LastAppendUUID to newNode
	// increment appends by 1 in the FileStruct
	// Create new AppendNodeStruct, and Save the new filedata to the AppendNode, and set the next node to null
	// Encrypt + MAC the append node using HKDF(Symmkey, appends), save in Datastore with the newly generated UUID
	
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {

	//TODO: This is a toy implementation.
	storageKey, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("File not found!"))
	}
	json.Unmarshal(dataJSON, &dataBytes)
	return dataBytes, nil
	//End of toy implementation

	// If namespace does not contain hash(filename), return error
	// Load FileFrameStruct UUID
	// If file owner, load fileStructUUID and key directly
	// Otherwise load and decrypt SharedFileFrame, and from there load fileStructUUID and decryption key
	// Load and decrypt fileStruct and verify validity (invalid then error)
	// Until null, iterate through appendNodes:
	//		For each appendNode, load in the appendNode and decrypt and verify validity (invalid then error)
	// 		load in the data and append to dataBytes
	// return the dataBytes and an error if any
	return
}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (
	accessToken uuid.UUID, err error) {
	// Check that the file is in the namespace or error
	// Grab the FileFrameStruct
	// If user is the owner of the file, 
	//		create a new SharedFileFrame
	// 		Save the encryption key
	// 		Save the FileUUID
	// 		Generate a new AccessCode and encrypt + MAC the SharedFileFrame
	//		Save the SharedFileFrame in the datastore at a newUUID
	//		Update the user/accesstoken map to include the recipient and their accesstoken
	// Create a new SharedFileInvitationStruct
	// Save the UUID of the SharedFileFrame
	// Save the accesstoken of the recipient
	// Encrypt with recipient's public RSA key from the keystore
	// Store the SharedFileInvitationStruct at a UUID generated from the hash(filename + recipient)
	// return where this is stored
	return
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string,
	accessToken uuid.UUID) error {
	// TODO: Need to verify integrity of SharedFileInvitation as well, can something be MACd and signed?
	// if namespace.contains(filename), Error: You already contain a file with the same name.
	// Check that a struct exists at parameter accessToken
	// Load in the struct and decrypt it using RSA private key and verify DS
	// If cannot verify DS, Error: Sender cannot be verified
	// Load the accessToken and decrypt the IntermediateStruct
	// If revoked == true, Error: revoked
	// Save IntermediateStruct UUID in FileFrameStruct
	return nil
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	// if !namespace.containsKey(filename), Error: No such file
	// if !user/accesstoken_map(targetUsername), Error: File not shared with specified user
	// Retrieve FileFrameStruct from namespace
	// Retrieve UUID of IntermediateStruct + Accesskey to decrypt from user/uuid table
	// Set revoked boolean to true, set file UUID to 0, set encryption decryption key to 0
	// Iterate through keyset of shared users (except targetUsername) and change encryption/decryption keys
	// Load FileStruct, decrypt w/ old key, Load FirstAppend, decrypt w/ old key
	// till null, reencrypt w new key and put back
	// reencrypt fileStruct
	// remove user from FileFrameStruct.user/uuid_map
	return
}
