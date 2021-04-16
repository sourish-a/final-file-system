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
	Privdsk userlib.DSSignKey
	PrivRSA userlib.PKEDecKey
	Namespace map[string]FileFrame //maps hash of filename to UUID of where File struct exists

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type FileFrame struct {
	IsOwner bool
	FileUUID uuid.UUID //set to 0 unless owner, points to File struct
	SymmKey []byte // set to 0 unless owner
	SharedUsers map[string][]byte //maps username to acccess tokens for all shared users; exclusive to owner
	SharedFrame uuid.UUID //points to SharedFileFrame, only for shared users
	AccessToken []byte // set to 0 if owner, otherwise the key used to decrypt SharedFileFrame 
}

type File struct {
	Appends int
	FirstAppend uuid.UUID
	LastAppend uuid.UUID
}

type AppendNode struct {
	FileData []byte
	NextPtr uuid.UUID
	NumAppend int
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
	userUUID, _ := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	_, userExists := userlib.DatastoreGet(userUUID)
	if userExists == true {
		panic("User already exists")
		return nil, errors.New("User already exists")
	}
	userdata.Username = username
	userdata.Masterkey = userlib.Argon2Key([]byte(password), userlib.Hash([]byte(username)), 16)
	var pubRSA userlib.PKEEncKey
	var pubDSK userlib.DSVerifyKey
	pubRSA, userdata.PrivRSA, _ = userlib.PKEKeyGen()
	userdata.Privdsk, pubDSK, _ = userlib.DSKeyGen()
	hmacKey, _ := userlib.HashKDF(userdata.Masterkey, []byte("hmac"))
	hmacKey = hmacKey[:16]
	userdata.Namespace = make(map[string]FileFrame)
	toJson, _ := json.Marshal(userdata)


	iv := userlib.RandomBytes(16)
	jsonEnc := encryptData(userdata.Masterkey, iv, toJson)
	userlib.KeystoreSet("RSA" + username , pubRSA)
	userlib.KeystoreSet("DSK" + username , pubDSK)
	signature, _ := userlib.DSSign(userdata.Privdsk, jsonEnc)
	hmac, _ := userlib.HMACEval(hmacKey, jsonEnc)
	sigAndHmac := append(signature, hmac...)
	finalJson := append(jsonEnc, sigAndHmac...)
	userlib.DatastoreSet(userUUID, finalJson)
	//End of toy implementation

	return &userdata, nil
}

// GetUser is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/getuser.html
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	userUUID, _ := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	retrieved, exists := userlib.DatastoreGet(userUUID) // retrieved = encJson + signature + hmac
	if exists == false {
		panic("username does not exist")
		return nil, errors.New("username does not exist")
	}
	hmac := retrieved[len(retrieved) - 64:]
	signature := retrieved[len(retrieved) - 320:len(retrieved) - 64]
	encJson := retrieved[:len(retrieved) - 320]
	pubDSK, _ := userlib.KeystoreGet("DSK" + username)
	if userlib.DSVerify(pubDSK, encJson, signature) != nil {
		panic("Data has been tampered with!!")
		return nil, errors.New("Data has been tampered with!")
	}
	master := userlib.Argon2Key([]byte(password), userlib.Hash([]byte(username)), 16)
	hmacKey, _ := userlib.HashKDF(master, []byte("hmac"))
	hmacKey = hmacKey[:16]
	hmacCheck, _ := userlib.HMACEval(hmacKey, encJson)
	if !userlib.HMACEqual(hmacCheck, hmac) {
		panic("Data has been tampered with!!")
		return nil, errors.New("Data has been tampered with!!")
	}
	unEncJson := decryptData(master, encJson)
	errorExists := json.Unmarshal(unEncJson, userdataptr)
	if errorExists != nil {
		panic("incorrect password")
		return nil, errors.New("incorrect password")
	}
	return userdataptr, nil
}

// StoreFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/storefile.html
func (userdata *User) StoreFile(filename string, data []byte) (err error) {
	//End of toy implementation
	hashFName := userlib.Hash([]byte(filename))
	if _, ok := userdata.Namespace[string(hashFName)]; ok {
		fileframe := userdata.Namespace[string(hashFName)]
		var file File
		fileptr := &file
		if fileframe.IsOwner == true {
			//if file exists already, and we are the owner
			encFileStruct, somethingWrong := userlib.DatastoreGet(fileframe.FileUUID)
			if somethingWrong == false {
				return errors.New("Could not find file")
			}
			jsonFileStruct, tampering := verifyDecrypt(encFileStruct, fileframe.SymmKey)
			if tampering != nil {
				return tampering
			}
			errorExists := json.Unmarshal(jsonFileStruct, fileptr)
			if errorExists != nil {
				return errorExists
			}

			zeroUUID, _ := uuid.FromBytes([]byte(nil))
			newAppend := AppendNode{data, zeroUUID, 1}
			appendUUID, _ := uuid.FromBytes(userlib.RandomBytes(16))
			appendKey, _ := userlib.HashKDF(fileframe.SymmKey, []byte{1})
			appendKey = appendKey[:16]

			jsonAppend, _ := json.Marshal(newAppend)
			randIV := userlib.RandomBytes(16)
			encAppend := encryptData(appendKey, randIV, jsonAppend) // encrypting AppendNode w/ HKDF(SymmKey, appends)
			hmacAppendKey, _ := userlib.HashKDF(appendKey, []byte("hmac"))
			hmacAppendKey = hmacAppendKey[:16]
			hmacAppend, _ := userlib.HMACEval(hmacAppendKey, encAppend)
			appendAndHmac := append(encAppend, hmacAppend...)
			userlib.DatastoreSet(appendUUID, appendAndHmac)

			file.Appends = 1
			file.FirstAppend = appendUUID
			file.LastAppend = appendUUID
			jsonFile, _ := json.Marshal(file)
			encFile := encHmac(fileframe.SymmKey, jsonFile)
			userlib.DatastoreSet(fileframe.FileUUID, encFile)
		} else {
			// if we are not the owner
			//LOAD SHARED FILE FRAME
			var sharedFF SharedFileFrame
			sharedFFptr := &sharedFF
			encSharedFF, somethingWrong := userlib.DatastoreGet(fileframe.SharedFrame)
			if somethingWrong == false {
				return errors.New("File no longer shared")
			}
			jsonSharedFF, tampering := verifyDecrypt(fileframe.AccessToken, encSharedFF)
			if tampering != nil {
				return tampering
			}
			errorExists := json.Unmarshal(jsonSharedFF, sharedFFptr)
			if errorExists != nil {
				return errors.New("Incorrect data structure")
			}

			if sharedFF.Revoked == true {
				return errors.New("File access revoked")
			}

			//LOAD FILE
			encFile, somethingWrong2 := userlib.DatastoreGet(sharedFF.SharedFileUUID)
			if somethingWrong2 == false {
				return errors.New("File access revoked")
			}
			jsonFile, tampering2 := verifyDecrypt(sharedFF.SymmKey, encFile)
			if tampering2 != nil {
				return tampering
			}
			errorExists2 := json.Unmarshal(jsonFile, fileptr)
			if errorExists2 != nil {
				return errors.New("Incorrect data structure")
			}

			//CREATE NEW APPEND & STORE TO DATASTORE
			zeroUUID, _ := uuid.FromBytes([]byte(nil))
			newAppend := AppendNode{data, zeroUUID, 1}
			appendUUID, _ := uuid.FromBytes(userlib.RandomBytes(16))
			appendKey, _ := userlib.HashKDF(sharedFF.SymmKey, []byte{1})
			appendKey = appendKey[:16]
			jsonAppend, _ := json.Marshal(newAppend)

			encAppend := encHmac(appendKey, jsonAppend)
			userlib.DatastoreSet(appendUUID, encAppend)
			//CHANGE FILE CONTENTS
			file.Appends = 1
			file.FirstAppend = appendUUID
			file.LastAppend = appendUUID

			//STORE FILE TO DATASTORE
			jsonFile, _ = json.Marshal(file)
			encFile = encHmac(sharedFF.SymmKey, jsonFile)
			userlib.DatastoreSet(sharedFF.SharedFileUUID, encFile)
		}
	} else {
		//file not in namespace
		fileUUID, _ := uuid.FromBytes(userlib.RandomBytes(16))
		fileSymmKey, _ := userlib.HashKDF(userdata.Masterkey, userlib.RandomBytes(16)) //key to encrypt/decrypt FileStruct
		fileSymmKey = fileSymmKey[:16]
		zeroUUID, _ := uuid.FromBytes([]byte(nil))
		newFileframe := FileFrame{true, fileUUID, fileSymmKey, make(map[string][]byte), zeroUUID, nil}
		userdata.Namespace[string(hashFName)] = newFileframe
		newAppend := AppendNode{data, zeroUUID, 1}
		appendUUID, _ := uuid.FromBytes(userlib.RandomBytes(16))
		appendKey, _ := userlib.HashKDF(fileSymmKey, []byte{1})
		appendKey = appendKey[:16]
		jsonAppend, _ := json.Marshal(newAppend)
		randIV := userlib.RandomBytes(16)
		encAppend := encryptData(appendKey, randIV, jsonAppend) // encrypting AppendNode w/ HKDF(SymmKey, appends)
		hmacAppendKey, _ := userlib.HashKDF(appendKey, []byte("hmac"))
		hmacAppendKey = hmacAppendKey[:16]
		hmacAppend, _ := userlib.HMACEval(hmacAppendKey, encAppend)
		appendAndHmac := append(encAppend, hmacAppend...)
		userlib.DatastoreSet(appendUUID, appendAndHmac)
		newFile := File{1, appendUUID, appendUUID}
		jsonFile, _ := json.Marshal(newFile)
		encFile := encHmac(fileSymmKey, jsonFile)
		userlib.DatastoreSet(fileUUID, encFile)
	}
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

	// hashedFilename := Hash(filename)

	return
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	// from the namespace map, use the hash(filename) as the key to get the FileFrameStruct
	fileFrame, exists := userdata.Namespace[string(userlib.Hash([]byte(filename)))]
	if !exists {
		return errors.New("Filename does not exist in the namespace.")
	}
	// load the file information from the fileFrame
	fileDecryptionKey, fileUUID, error := userdata.getFileInformationFromFileFrame(&fileFrame, filename)
	if error != nil {
		return error
	}

	// load the FileStruct from the DataStore using the FileUUID, check for validity, and unencrypt
	// else if data cannot be unmarshalled -- Error: user no longer has access, remove filename from namespace
	file, errorExists := userdata.loadFileStruct(fileUUID, fileDecryptionKey, filename)
	if errorExists != nil {
		return errorExists
	}

	// Generate a new random UUID called newNode
	newNodeUUID, _ := uuid.FromBytes(userlib.RandomBytes(16))

	// Load AppendNode from LastAppendUUID (from the Datastore) and unencrypt it by HKDF(Symmkey, appends) and check MAC
	// Set nextAppendNode to this new UUID
	// Reencrypt and MAC using HKDF(symmkey, appends), put back in datastore at LastAppendUUID
	previouslyLastAppendNode, error := userdata.loadAppendNode(file.LastAppend, fileFrame.SymmKey, file.Appends)
	if error != nil {
		return error
	}
	previouslyLastAppendNode.NextPtr = newNodeUUID
	error = userdata.saveAppendNode(file.LastAppend, previouslyLastAppendNode, fileFrame.SymmKey, file.Appends)
	if error != nil {
		return error
	}

	// Change LastAppendUUID to newNode
	// increment appends by 1 in the FileStruct
	file.LastAppend = newNodeUUID
	file.Appends = file.Appends + 1

	// Create new AppendNodeStruct, and Save the new filedata to the AppendNode, and set the next node to null
	zeroUUID, _ := uuid.FromBytes([]byte(nil))
	newAppendNode := AppendNode{data, zeroUUID, file.Appends}
	// Encrypt + MAC the append node using HKDF(Symmkey, appends), save in Datastore with the newly generated UUID
	error = userdata.saveAppendNode(file.LastAppend, &newAppendNode, fileFrame.SymmKey, file.Appends)
	if error != nil {
		return error
	}
	error = userdata.saveFileStruct(fileUUID, file, fileFrame.SymmKey)
	if error != nil {
		return error
	}
	return nil
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {
	// If namespace does not contain hash(filename), return error
	fileFrame, exists := userdata.Namespace[string(userlib.Hash([]byte(filename)))]
	if !exists {
		return nil, errors.New("No such file.")
	}
	// Load FileStruct UUID and decryption key
	fileDecryptionKey, fileUUID, error := userdata.getFileInformationFromFileFrame(&fileFrame, filename)
	if error != nil {
		return nil, error
	}
	// Load and decrypt fileStruct and verify validity (invalid then error)
	file, error := userdata.loadFileStruct(fileUUID, fileDecryptionKey, filename)
	if error != nil {
		return nil, error
	}
	// Until null, iterate through appendNodes:
	//		For each appendNode, load in the appendNode and decrypt and verify validity (invalid then error)
	// 		load in the data and append to dataBytes
	var currAppendNode *AppendNode
	var currAppendNodeUUID uuid.UUID = file.FirstAppend
	for i := 0; i < file.Appends; i++ {
		currAppendNode, error = userdata.loadAppendNode(currAppendNodeUUID, fileDecryptionKey, i + 1)
		if error != nil {
			return nil, error
		}
		dataBytes = append(dataBytes[:], currAppendNode.FileData[:] ...)
		currAppendNodeUUID = currAppendNode.NextPtr
	}
	
	// return the dataBytes and an error if any
	return dataBytes, nil
}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (invitationLocation uuid.UUID, err error) {
	// Check that the file is in the namespace or error
	zeroUUID, _ := uuid.FromBytes([]byte(nil))
	fileFrame, exists := userdata.Namespace[string(userlib.Hash([]byte(filename)))]
	if !exists {
		return zeroUUID, errors.New("No such file.")
	}
	// If user is the owner of the file, 
	//		create a new SharedFileFrame and save relevant information
	// 		Generate a new AccessCode and encrypt + MAC sharedFileFrame and save it
	//		Save the SharedFileFrame in the datastore at a newUUID
	//		Update the user/accesstoken map to include the recipient and their accesstoken
	var accessToken []byte 
	var sharedFrameUUID uuid.UUID
	if fileFrame.IsOwner {
		sharedFrame := SharedFileFrame{fileFrame.SymmKey, fileFrame.FileUUID, false}
		unencryptedData, _ := json.Marshal(sharedFrame)
		accessToken = userlib.RandomBytes(16)
		encryptedData := encHmac(accessToken, unencryptedData)
		sharedFrameUUID, _ = uuid.FromBytes(userlib.RandomBytes(16))
		userlib.DatastoreSet(sharedFrameUUID, encryptedData)
		fileFrame.SharedUsers[recipient] = append(accessToken[:], sharedFrameUUID[:] ...)
	} else if !fileFrame.IsOwner {
		accessToken = fileFrame.AccessToken
		sharedFrameUUID = fileFrame.SharedFrame
	}

	// Create a new SharedFileInvitationStruct
	shareInvitation := Invite{sharedFrameUUID, accessToken}
	unencryptedData, _ := json.Marshal(shareInvitation)
	// Encrypt with recipient's public RSA key from the keystore
	recipientPubRSAKey, _ := userlib.KeystoreGet("RSA" + recipient)
	encryptedData, error := userlib.PKEEnc(recipientPubRSAKey, unencryptedData)
	if error != nil {
		return zeroUUID, error
	}
	signature, error := userlib.DSSign(userdata.Privdsk, encryptedData)
	if error != nil {
		return zeroUUID, error
	}
	signedAndEncryptedData := append(encryptedData[:], signature[:] ...)
	// Store the SharedFileInvitationStruct at a UUID generated from the hash(filename + recipient)
	hashedValueForUUID := userlib.Hash(userlib.Hash([]byte(userdata.Username + filename + recipient)))
	invitationLocation, _ = uuid.FromBytes(hashedValueForUUID[:16])
	userlib.DatastoreSet(invitationLocation, signedAndEncryptedData)
	// return where this is stored
	return invitationLocation, nil
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
	fileFrame, exists := userdata.Namespace[string(userlib.Hash([]byte(filename)))]
	if !exists {
		return errors.New("No such file.")
	}
	// if !user/accesstoken_map(targetUsername), Error: File not shared with specified user
	tokenAndUUID, exists := fileFrame.SharedUsers[targetUsername]
	if !exists {
		return errors.New("File not shared with specified user.")
	}
	// Retrieve UUID of IntermediateStruct + Accesskey to decrypt from user/uuid table
	accessToken := tokenAndUUID[:16]
	intermediateStructUUID, _ := uuid.FromBytes(tokenAndUUID[16:])

	// load SharedFileFrame
	sharedFileFrame, error := userdata.loadSharedFileFrame(intermediateStructUUID, accessToken, filename)
	if error != nil {
		return error
	}
	// Set revoked boolean to true, set file UUID to 0, set encryption decryption key to 0
	sharedFileFrame.Revoked = true
	sharedFileFrame.SharedFileUUID, _ = uuid.FromBytes([]byte(nil))
	sharedFileFrame.SymmKey = []byte{}

	// update symmkeys
	newSymmKey, error := userlib.HashKDF(userdata.Masterkey, userlib.RandomBytes(16))
	if error != nil {
		return error
	}

	// Iterate through keyset of shared users (except targetUsername) and change encryption/decryption keys
	delete(fileFrame.SharedUsers, targetUsername)
	for k := range fileFrame.SharedUsers {
		tokenAndUUID, _ := fileFrame.SharedUsers[k]
		accessToken = tokenAndUUID[:16]
		intermediateStructUUID, _ = uuid.FromBytes(tokenAndUUID[16:])
		sharedFileFrame, error := userdata.loadSharedFileFrame(intermediateStructUUID, accessToken, filename)
		if error != nil {
			return error
		}
		sharedFileFrame.SymmKey = newSymmKey
		error = userdata.saveSharedFileFrame(intermediateStructUUID, sharedFileFrame, accessToken)
	}

	// Reencrypt all the filedata with the new key
	// Load FileStruct, decrypt w/ old key, Load FirstAppend, decrypt w/ old key
	file, error := userdata.loadFileStruct(fileFrame.FileUUID, fileFrame.SymmKey, filename)
	if error != nil {
		return error
	}
	// till null, reencrypt w new key and put back
	var currAppendNode *AppendNode
	var currAppendNodeUUID uuid.UUID = file.FirstAppend
	for i:=0; i < file.Appends; i++ {
		currAppendNode, error = userdata.loadAppendNode(currAppendNodeUUID, fileFrame.SymmKey, i + 1)
		if error != nil {
			return error
		}
		error = userdata.saveAppendNode(currAppendNodeUUID, currAppendNode, newSymmKey, i + 1)
		if error != nil {
			return error
		}
		currAppendNodeUUID = currAppendNode.NextPtr
	}
	// reencrypt fileStruct
	error = userdata.saveFileStruct(fileFrame.FileUUID, file, newSymmKey)
	if error != nil {
		return error
	}
	fileFrame.SymmKey = newSymmKey
	return nil
}

// Load a SharedFileFrame data structure. 
// Verifies no tampering, decrypts, and unmarshalls. If access has been revoked, removes the file from the users namespace.
// Assumes that the user is not an owner and has a SharedFileFrame structure
func (userdata *User) loadSharedFileFrame(uuid uuid.UUID, accessToken []byte, filename string)(sharedFileFramePointer *SharedFileFrame, err error) {
	// load the encrypted json data for the Shared File Frame
	encryptedSharedFrame, ok := userlib.DatastoreGet(uuid)
	if !ok {
		return &SharedFileFrame{}, errors.New("Could not load encrypted shared frame from DataStore.")
	}
	// verify the data has not been tampered with
	error := verifyValidDataHMAC(encryptedSharedFrame, accessToken)
	if error != nil {
		return &SharedFileFrame{}, error
	}
	// decrypt the information
	unencryptedSharedFrame := decryptData(accessToken, encryptedSharedFrame)
	// unmarshall the data
	var sharedFrameFinal SharedFileFrame
	sharedFileFramePointer = &sharedFrameFinal
	errorExists := json.Unmarshal(unencryptedSharedFrame, sharedFileFramePointer)
	if errorExists != nil {
		return &SharedFileFrame{}, errors.New("Incorrect data structure")
	}

	// If the access has been revoked, delete the file from the namespace
	if sharedFrameFinal.Revoked {
		delete(userdata.Namespace, string(userlib.Hash([]byte(filename))))
		return sharedFileFramePointer, errors.New("File access has been revoked")
	}

	// return the unencrypted and verified sharedFrame
	return sharedFileFramePointer, nil
}

func (userdata *User) saveSharedFileFrame(sharedFrameUUID uuid.UUID, sharedFramePtr *SharedFileFrame, key []byte)(err error) {
	// Marshal AppendNode to byte array
	unencryptedData, error := json.Marshal(*sharedFramePtr)
	if error != nil {
		return error
	}
	// Encrypt and mac the data
	encryptedData := encHmac(key, unencryptedData)
	// Save to the datastore
	userlib.DatastoreSet(sharedFrameUUID, encryptedData)
	return nil
}

func (userdata *User) loadFileStruct (fileUUID uuid.UUID, fileDecryptionKey []byte, filename string) (fileStructPointer *File, err error){
	// load the encrypted json data for the file struct
	encryptedFileStruct, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return &File{}, errors.New("Could not load encrypted file struct from DataStore.")
	}
	// verify the data has not been tampered with
	error := verifyValidDataHMAC(encryptedFileStruct, fileDecryptionKey)
	if error != nil {
		return &File{}, error
	}
	// decrypt the information
	unencryptedFileStruct := decryptData(fileDecryptionKey, encryptedFileStruct)
	// unmarshall the data
	var fileStructFinal File
	fileStructPointer = &fileStructFinal
	errorExists := json.Unmarshal(unencryptedFileStruct, fileStructPointer)

	// if the data could not be unmarshalled, the decryption did not work, key was changed
	// remove the file from the namespace
	if errorExists != nil {
		delete(userdata.Namespace, string(userlib.Hash([]byte(filename))))
		return &File{}, errors.New("Incorrect data structure.")
	}
	return fileStructPointer, nil
}

func (userdata *User) saveFileStruct(fileUUID uuid.UUID, filePtr *File, key []byte)(err error) {
	// Marshal AppendNode to byte array
	unencryptedData, error := json.Marshal(*filePtr)
	if error != nil {
		return error
	}
	// Encrypt and mac the data
	encryptedData := encHmac(key, unencryptedData)
	// Save to the datastore
	userlib.DatastoreSet(fileUUID, encryptedData)
	return nil
}

func (userdata *User) loadAppendNode(nodeUUID uuid.UUID, nodeDecryptionKey []byte, appends int) (appendNodePtr *AppendNode, err error) {
	// load the encrypted json data for the file struct
	encryptedNodeStruct, ok := userlib.DatastoreGet(nodeUUID)
	if !ok {
		return &AppendNode{}, errors.New("Could not load encrypted file struct from DataStore.")
	}
	// decrypt the information
	hashKDFkey, error := userlib.HashKDF(nodeDecryptionKey, []byte{appends})
	if error != nil {
		return &AppendNode{}, error
	}
	unencryptedNodeStruct, errorExists := verifyDecrypt(nodeDecryptionKey, encryptedNodeStruct)
	if errorExists != nil {
		return &AppendNode{}, errorExists
	}
	// unmarshall the data
	var node AppendNode
	appendNodePtr = &node
	errorExists = json.Unmarshal(unencryptedNodeStruct, appendNodePtr)
	if errorExists != nil {
		return &AppendNode{}, errors.New("Incorrect data structure")
	}
	return appendNodePtr, nil
}

func (userdata *User) saveAppendNode(nodeUUID uuid.UUID, nodePtr *AppendNode, key []byte, appends int)(err error) {
	// Marshal AppendNode to byte array
	unencryptedData, error := json.Marshal(*nodePtr)
	if error != nil {
		return error
	}
	// Encrypt and mac the data
	hashKDFkey, error := userlib.HashKDF(key, []byte{appends})
	if error != nil {
		return error
	}

	encryptedData := encHmac(hashKDFkey, unencryptedData)
	// Save to the datastore
	userlib.DatastoreSet(nodeUUID, encryptedData)
	return nil
}

// Gets location and decryption information for a file with a filename from the specified fileFrame
func (userdata *User) getFileInformationFromFileFrame(fileFramePtr *FileFrame, filename string) (key []byte, location uuid.UUID, err error) {
	// if NOT the owner:
	// 		load the SharedFileFrame from the datastore using the SharedFrame UUID in the FileFrameStruct
	// 		get encryp/decryption key and FileUUID from the SharedFileFrame struct
	// if owner:
	//		load the key and FileUUID from the FileFrameStruct directly
	zeroUUID, _ := uuid.FromBytes([]byte(nil))
	if !fileFramePtr.IsOwner {
		sharedFileFrame, errorExists := userdata.loadSharedFileFrame(fileFramePtr.SharedFrame, fileFramePtr.AccessToken, filename)
		if errorExists != nil {
			return nil, zeroUUID, errorExists
		}
		key = sharedFileFrame.SymmKey
		location = sharedFileFrame.SharedFileUUID
	} else if fileFramePtr.IsOwner {
		key = fileFramePtr.SymmKey
		location = fileFramePtr.FileUUID
	}
	return key, location, nil
}

// Verify the validity of encrypted data using HMAC
func verifyValidDataHMAC(encryptedData []byte, decryptionKey []byte)(err error) {
	hmac := encryptedData[len(encryptedData) - 64:]
	hashKDFKey, error := userlib.HashKDF(decryptionKey, []byte("hmac"))
	if error != nil {
		return error
	}
	hashKDFKey = hashKDFKey[:16]
	hmacCheck, error := userlib.HMACEval(hashKDFKey, encryptedData)
	if error != nil {
		return error
	}
	if !userlib.HMACEqual(hmacCheck, hmac) {
		return errors.New("Data has been tampered with.")
	}
	return nil
}

//SymDec(), but accounts for padding
func decryptData(key []byte, ciphertext []byte) ([]byte) {
	// TODO: Add a check to ensure that ciphertext % blocksize == 0 before calling SymDec
	paddedData := userlib.SymDec(key, ciphertext)
	lenpadding := paddedData[len(paddedData) - 1]
	data := paddedData[:len(paddedData) - int(lenpadding)]
	return data
}

//SymEnC(), but add padding
func encryptData(key []byte, iv []byte, ciphertext []byte) ([]byte) {
	lenpadding := 16 - len(ciphertext) % 16
	padding := make([]byte, lenpadding)
	for i, _ := range padding {
		padding[i] = byte(lenpadding)
	}

	paddedData := append(ciphertext, padding...)
	encData := userlib.SymEnc(key, iv, paddedData)
	return encData
}

//encrypts and HMACs the ciphertext using key
func encHmac(key []byte, ciphertext []byte) ([]byte) { 
	encData := encryptData(key, userlib.RandomBytes(16), ciphertext)
	hmacKey, _ := userlib.HashKDF(key, []byte("hmac"))
	hmacKey = hmacKey[:16]
	hmac, _ := userlib.HMACEval(hmacKey, encData)

	return append(encData, hmac...)
}

//verifys the HMAC then decrypts data
func verifyDecrypt(key []byte, ciphertext []byte) ([]byte, error){
	hmac := ciphertext[len(ciphertext) - 64:]
	encData := ciphertext[:len(ciphertext) - 64]
	hmacKey, _ := userlib.HashKDF(key, []byte("hmac"))
	hmacKey = hmacKey[:16]
	dataHmac, _ := userlib.HMACEval(hmacKey, encData)
	if userlib.HMACEqual(hmac, dataHmac) != true {
		return nil, errors.New("Data has been tampered with!!")
	}
	return decryptData(key, encData), nil
}
