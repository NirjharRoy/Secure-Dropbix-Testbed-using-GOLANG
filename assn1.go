package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

//import "github.com/fenilfadadu/CS628-assn1/userlib"

import (

	// You neet to add with
	// go get github.com/fenilfadadu/CS628-assn1/userlib

	"github.com/fenilfadadu/CS628-assn1/userlib"
	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//s
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
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
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()

	userlib.DebugMsg("Key is %v", key)

}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
		//userlib
	}
	return
}

// The structure definition for a user record
type User struct {
	Username  string
	Password  string
	PvtkeyRsa *userlib.PrivateKey

	Ownedfilekeysmap     map[string]string //[file_name][encryption_keys]
	Sharedfileinfomap    map[string]string //[file_name][(file_location,encryption_keys)]
	Sharedfileinfomaploc map[string][]byte
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	err = nil
	userdata.Username = username
	userdata.Password = password

	//CALCULATING BIG KEY USING ARGON2

	bigkey := userlib.Argon2Key([]byte(username+password), []byte{}, 32)

	newuserhash := bigkey[0 : len(bigkey)/2]

	userdatastorekeysymm := bigkey[len(bigkey)/2 : len(bigkey)]

	Pvtkeyrsa, err := userlib.GenerateRSAKey()

	if err != nil {
		return nil, err

	}

	userdata.PvtkeyRsa = Pvtkeyrsa

	userdata.Ownedfilekeysmap = make(map[string]string)

	userdata.Sharedfileinfomap = make(map[string]string)
	userdata.Sharedfileinfomaploc = make(map[string][]byte)

	userdatabytes, err := json.Marshal(userdata)

	if err != nil {
		return nil, err

	}

	userdataencryptedbytes := make([]byte, userlib.BlockSize+len(userdatabytes)) //needs to be stored

	ivt := userlib.RandomBytes(userlib.BlockSize)

	for i := 0; i < userlib.BlockSize; i++ {
		userdataencryptedbytes[i] = ivt[i] //filling with random iv
	}

	iv := userdataencryptedbytes[:userlib.BlockSize]

	stream := userlib.CFBEncrypter(userdatastorekeysymm, iv)
	stream.XORKeyStream(userdataencryptedbytes[userlib.BlockSize:], userdatabytes)

	//-------calculate MAC--------
	hmac := userlib.NewHMAC(userdatastorekeysymm)
	hmac.Write(userdataencryptedbytes)

	hmacuserdata := hmac.Sum(nil) //needt to be stored

	type UserEntryFinalType struct {
		Userdataencryptedbytes []byte
		Hmacuserdata           []byte
	}

	var UserEntryFinal UserEntryFinalType
	UserEntryFinal.Hmacuserdata = hmacuserdata
	UserEntryFinal.Userdataencryptedbytes = userdataencryptedbytes

	UserEntryFinalbytes, err := json.Marshal(UserEntryFinal)

	if err != nil {

		return nil, err
	}

	userlib.DatastoreSet(string(newuserhash), UserEntryFinalbytes)

	userlib.KeystoreSet(username, Pvtkeyrsa.PublicKey)

	return &userdata, err
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {

	err = nil
	bigkey := userlib.Argon2Key([]byte(username+password), []byte{}, 32)

	newuserhash := bigkey[0 : len(bigkey)/2]

	userdatastorekeysymm := bigkey[len(bigkey)/2 : len(bigkey)]

	UserEntryFinalbytes, okval := userlib.DatastoreGet(string(newuserhash))

	//UserEntryFinalbytes[2] = 78 //ATTACK

	if !okval {
		err = errors.New("No file in the given location")
		return nil, err
	}

	type UserEntryFinalType struct {
		Userdataencryptedbytes []byte
		Hmacuserdata           []byte
	}

	var UserEntryFinal UserEntryFinalType

	err = json.Unmarshal(UserEntryFinalbytes, &UserEntryFinal)

	if err != nil {
		err = errors.New("error during fetched  data unmarshalling")
		return nil, err
	}

	//hmac calculate and check for integrity

	hmac := userlib.NewHMAC(userdatastorekeysymm)
	hmac.Write(UserEntryFinal.Userdataencryptedbytes)
	hmaccalc := hmac.Sum(nil) //in bytes

	hmacrecvbytes := UserEntryFinal.Hmacuserdata

	if !userlib.Equal(hmacrecvbytes, hmaccalc) {
		err = errors.New("User Data is modified malicously")
		return nil, err
	}

	userdataencryptedbytes := UserEntryFinal.Userdataencryptedbytes
	ivd := userdataencryptedbytes[:userlib.BlockSize]
	userdataencryptedbytes = userdataencryptedbytes[userlib.BlockSize:]
	streamd := userlib.CFBDecrypter(userdatastorekeysymm, ivd)
	streamd.XORKeyStream(userdataencryptedbytes, userdataencryptedbytes)

	var userdata User

	err = json.Unmarshal(userdataencryptedbytes, &userdata)

	if err != nil {
		err = errors.New("error during user data unmarshalling")
		return nil, err
	}

	return &userdata, err
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	userdata.synchuser()

	var filedatastorekeysymmstring string
	filedatastorekeysymmstring, okpresent := userdata.Ownedfilekeysmap[filename]

	if !okpresent {
		filedatastorekeysymmstring = uuid.New().String()

	}
	_, okpresent = userdata.Sharedfileinfomap[filename] // removing duplicates

	if okpresent {
		delete(userdata.Sharedfileinfomap, filename)
		delete(userdata.Sharedfileinfomaploc, filename)
	}
	filedatastorekeysymm := ([]byte(filedatastorekeysymmstring + "0"))[0:userlib.AESKeySize]
	var indextable []string //uc

	// encrypting the contents of the file

	filedataencryptedbytes := make([]byte, userlib.BlockSize+len(data)) //needs to be stored

	ivt := userlib.RandomBytes(userlib.BlockSize)
	for i := 0; i < userlib.BlockSize; i++ {
		filedataencryptedbytes[i] = ivt[i] //filling with random iv
	}

	iv := filedataencryptedbytes[:userlib.BlockSize]
	stream := userlib.CFBEncrypter(filedatastorekeysymm, iv)
	stream.XORKeyStream(filedataencryptedbytes[userlib.BlockSize:], data)

	//-------calculate MAC of the file encrypted contents--------
	hmac := userlib.NewHMAC(filedatastorekeysymm)
	hmac.Write(filedataencryptedbytes)

	hmacfiledata := hmac.Sum(nil) //needt to be stored

	type FileDataEntryFinalType struct {
		Filedataencryptedbytes []byte
		Hmacfiledata           []byte
	}

	var FileDataEntryFinal FileDataEntryFinalType
	FileDataEntryFinal.Hmacfiledata = hmacfiledata
	FileDataEntryFinal.Filedataencryptedbytes = filedataencryptedbytes

	FileDataEntryFinalbytes, _ := json.Marshal(FileDataEntryFinal) //uc

	// calculating the location of the chunk

	temp := (userlib.Argon2Key([]byte(userdata.Username+userdata.Password+filename+"0"), []byte{}, 16))
	locationofchunk := string(temp[:len(temp)])

	//userlib.DatastoreSet(locationofchunk, FileDataEntryFinalbytes)

	//adding entry to the index table

	indextable = append(indextable, locationofchunk)
	indextablebytes, _ := json.Marshal(indextable) //check

	var indextable2 []string
	json.Unmarshal(indextablebytes, &indextable2)
	userlib.DatastoreSet(indextable2[0], FileDataEntryFinalbytes)

	// encrypting the index table
	fileindexstorekeysymm := ([]byte(filedatastorekeysymmstring))[0:userlib.AESKeySize]

	fileindexencryptedbytes := make([]byte, userlib.BlockSize+len(indextablebytes)) //needs to be stored

	ivt = userlib.RandomBytes(userlib.BlockSize)
	for i := 0; i < userlib.BlockSize; i++ {
		fileindexencryptedbytes[i] = ivt[i] //filling with random iv
	}

	iv = fileindexencryptedbytes[:userlib.BlockSize]
	stream = userlib.CFBEncrypter(fileindexstorekeysymm, iv)
	stream.XORKeyStream(fileindexencryptedbytes[userlib.BlockSize:], indextablebytes)

	//-------calculate MAC of the index encrypted contents--------
	hmac = userlib.NewHMAC(fileindexstorekeysymm)
	hmac.Write(fileindexencryptedbytes)

	hmacindexdata := hmac.Sum(nil) //needt to be stored

	type FileIndexEntryFinalType struct {
		Fileindexencryptedbytes []byte
		Hmacindexdata           []byte
	}

	var FileIndexEntryFinal FileIndexEntryFinalType
	FileIndexEntryFinal.Hmacindexdata = hmacindexdata
	FileIndexEntryFinal.Fileindexencryptedbytes = fileindexencryptedbytes

	FileIndexEntryFinalBytes, _ := json.Marshal(FileIndexEntryFinal)

	// calculating the location of the indextable

	temp = userlib.Argon2Key([]byte(userdata.Username+userdata.Password+filename), []byte{}, 16)
	locationofindextable := string(temp[:len(temp)])

	userlib.DatastoreSet(locationofindextable, FileIndexEntryFinalBytes)

	// updating the user map comprising the ownedmapkeysarray

	userdata.Ownedfilekeysmap[filename] = filedatastorekeysymmstring

	// -------------------------updating the map in the datastore-----------------------------

	userdata.updateuser()

}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	// fetching the index table
	userdata.synchuser()
	err = nil
	var fileencryptionkey string
	var locationofindextable string
	var present bool
	fileencryptionkey, present = userdata.Ownedfilekeysmap[filename]

	fileencryptionkey, present = userdata.Ownedfilekeysmap[filename]

	if present {
		temp := userlib.Argon2Key([]byte(userdata.Username+userdata.Password+filename), []byte{}, 16)

		locationofindextable = string(temp[:len(temp)])
	} else {
		sharedfileinfo, present := userdata.Sharedfileinfomap[filename]
		sharedfileinfoloc, present := userdata.Sharedfileinfomaploc[filename]

		if present {

			locationofindextable = string(sharedfileinfoloc)
			fileencryptionkey = sharedfileinfo

		} else {
			err = errors.New("filename not found")
			return err
		}

	}

	indextableencrypteddata, present := userlib.DatastoreGet(locationofindextable)

	if !present {
		err = errors.New("File index table not found")
		return err
	}

	type FileIndexEntryFinalType struct {
		Fileindexencryptedbytes []byte
		Hmacindexdata           []byte
	}

	var FileIndexEntryFinal FileIndexEntryFinalType

	json.Unmarshal(indextableencrypteddata, &FileIndexEntryFinal)

	//-------calculate MAC of the index encrypted contents--------
	hmac := userlib.NewHMAC(([]byte(fileencryptionkey))[0:userlib.AESKeySize])
	_, err = hmac.Write(FileIndexEntryFinal.Fileindexencryptedbytes)

	if err != nil {
		return err
	}

	hmacindexdata := hmac.Sum(nil) //need to be stored

	if !userlib.Equal(hmacindexdata, FileIndexEntryFinal.Hmacindexdata) {

		err = errors.New("Index file corrupted maliciously has been corrupted maliciously")
		return err

	}

	// decrypting the index table

	Fileindexencryptedbytes := FileIndexEntryFinal.Fileindexencryptedbytes
	ivd := Fileindexencryptedbytes[:userlib.BlockSize]
	Fileindexencryptedbytes = Fileindexencryptedbytes[userlib.BlockSize:]
	indextablecontentdecryptionkey := ([]byte(fileencryptionkey))[0:userlib.AESKeySize]

	streamd := userlib.CFBDecrypter(indextablecontentdecryptionkey, ivd)
	streamd.XORKeyStream(Fileindexencryptedbytes, Fileindexencryptedbytes) //check

	var indextable []string

	err = json.Unmarshal(Fileindexencryptedbytes, &indextable)

	if err != nil {
		err = errors.New("error during user data unmarshalling of indextable")
		return err
	}

	newindex := len(indextable)

	temp := userlib.Argon2Key([]byte(userdata.Username+userdata.Password+filename+convert(newindex)), []byte{}, 16)

	newfilechunklocation := string(temp[:len(temp)])

	// updating the indextable

	indextable = append(indextable, newfilechunklocation)
	indextablebytes, _ := json.Marshal(indextable) //check

	var indextable2 []string
	json.Unmarshal(indextablebytes, &indextable2)

	// re encrypting the indextable before storing

	fileindexstorekeysymm := ([]byte(fileencryptionkey))[0:userlib.AESKeySize]

	fileindexencryptedbytes := make([]byte, userlib.BlockSize+len(indextablebytes)) //needs to be stored

	ivt := userlib.RandomBytes(userlib.BlockSize)
	for i := 0; i < userlib.BlockSize; i++ {
		fileindexencryptedbytes[i] = ivt[i] //filling with random iv
	}

	iv := fileindexencryptedbytes[:userlib.BlockSize]
	stream := userlib.CFBEncrypter(fileindexstorekeysymm, iv)
	stream.XORKeyStream(fileindexencryptedbytes[userlib.BlockSize:], indextablebytes)

	//-------calculate MAC of the index encrypted contents--------
	hmac = userlib.NewHMAC(fileindexstorekeysymm)
	hmac.Write(fileindexencryptedbytes)

	hmacindexdata = hmac.Sum(nil) //needt to be stored

	//storing the encrypted index table

	FileIndexEntryFinal.Hmacindexdata = hmacindexdata
	FileIndexEntryFinal.Fileindexencryptedbytes = fileindexencryptedbytes

	FileIndexEntryFinalBytes, _ := json.Marshal(FileIndexEntryFinal)

	// calculating the location of the indextable

	userlib.DatastoreSet(locationofindextable, FileIndexEntryFinalBytes)

	// encrypting the newly added content
	filedatastorekeysymm := ([]byte(fileencryptionkey + convert(newindex)))[0:userlib.AESKeySize]
	filedataencryptedbytes := make([]byte, userlib.BlockSize+len(data)) //needs to be stored

	ivt = userlib.RandomBytes(userlib.BlockSize)
	for i := 0; i < userlib.BlockSize; i++ {
		filedataencryptedbytes[i] = ivt[i] //filling with random iv
	}

	iv = filedataencryptedbytes[:userlib.BlockSize]
	stream = userlib.CFBEncrypter(filedatastorekeysymm, iv)
	stream.XORKeyStream(filedataencryptedbytes[userlib.BlockSize:], data)

	//-------calculate MAC of the file encrypted contents--------
	hmac = userlib.NewHMAC(filedatastorekeysymm)
	hmac.Write(filedataencryptedbytes)

	hmacfiledata := hmac.Sum(nil) //needt to be stored

	type FileDataEntryFinalType struct {
		Filedataencryptedbytes []byte
		Hmacfiledata           []byte
	}

	var FileDataEntryFinal FileDataEntryFinalType
	FileDataEntryFinal.Hmacfiledata = hmacfiledata
	FileDataEntryFinal.Filedataencryptedbytes = filedataencryptedbytes

	FileDataEntryFinalbytes, _ := json.Marshal(FileDataEntryFinal) //uc

	// calculating the location of the chunk  indextable2[newindex]

	userlib.DatastoreSet(indextable2[newindex], FileDataEntryFinalbytes)

	return err
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	userdata.synchuser()

	err = nil
	var fileencryptionkey string
	var locationofindextable string
	var present bool
	fileencryptionkey, present = userdata.Ownedfilekeysmap[filename]

	if present {
		temp := userlib.Argon2Key([]byte(userdata.Username+userdata.Password+filename), []byte{}, 16)
		locationofindextable = string(temp[:len(temp)])
	} else {
		sharedfileinfo, present := userdata.Sharedfileinfomap[filename]
		sharedfileinfoloc, present := userdata.Sharedfileinfomaploc[filename]
		if present {

			locationofindextable = string(sharedfileinfoloc)
			fileencryptionkey = sharedfileinfo

		} else {
			err = errors.New("filename not found")
			return nil, err
		}

	}

	indextableencrypteddata, present := userlib.DatastoreGet(locationofindextable)
	ltb := []byte(locationofindextable)
	ltb = ltb
	if !present {
		err = errors.New("File index table not found")
		return nil, err
	}

	type FileIndexEntryFinalType struct {
		Fileindexencryptedbytes []byte
		Hmacindexdata           []byte
	}

	var FileIndexEntryFinal FileIndexEntryFinalType

	json.Unmarshal(indextableencrypteddata, &FileIndexEntryFinal)

	//-------calculate MAC of the index encrypted contents--------
	hmac := userlib.NewHMAC(([]byte(fileencryptionkey))[0:userlib.AESKeySize])
	_, err = hmac.Write(FileIndexEntryFinal.Fileindexencryptedbytes)

	if err != nil {
		return nil, err
	}

	hmacindexdata := hmac.Sum(nil) //need to be stored

	if !userlib.Equal(hmacindexdata, FileIndexEntryFinal.Hmacindexdata) {

		err = errors.New("Index file corrupted maliciously has been corrupted maliciously")
		return nil, err

	}

	// decrypting the index table

	Fileindexencryptedbytes := FileIndexEntryFinal.Fileindexencryptedbytes
	ivd := Fileindexencryptedbytes[:userlib.BlockSize]
	Fileindexencryptedbytes = Fileindexencryptedbytes[userlib.BlockSize:]
	indextablecontentdecryptionkey := ([]byte(fileencryptionkey))[0:userlib.AESKeySize]

	streamd := userlib.CFBDecrypter(indextablecontentdecryptionkey, ivd)
	streamd.XORKeyStream(Fileindexencryptedbytes, Fileindexencryptedbytes) //check

	var indextable []string

	err = json.Unmarshal(Fileindexencryptedbytes, &indextable)

	if err != nil {
		err = errors.New("error during user data unmarshalling of indextable")
		return nil, err
	}

	//----- index table got---------

	// traversing through the indextable and getting file chunks and appending to data

	for index, filelocation := range indextable {
		//fetch content at "filelocation"
		index = index

		filecontentatindex, present := userlib.DatastoreGet(filelocation)
		//filecontentatindex[8] = filecontentatindex[8] + 1 //ATTACK

		if !present {
			err = errors.New("chunk not found for index ")
			return nil, err
		}

		type FileDataEntryFinalType struct {
			Filedataencryptedbytes []byte
			Hmacfiledata           []byte
		}

		var FileDataEntryFinal FileDataEntryFinalType

		json.Unmarshal(filecontentatindex, &FileDataEntryFinal)

		// check mac for that location content

		//-------calculate MAC of the chunk encrypted contents--------

		fileencryptionkeyatindex := ([]byte(fileencryptionkey + convert(index)))[0:userlib.AESKeySize] //CHECK
		hmac := userlib.NewHMAC(fileencryptionkeyatindex)
		hmac.Write(FileDataEntryFinal.Filedataencryptedbytes)

		hmacfiledata := hmac.Sum(nil) //need to be stored

		if !userlib.Equal(hmacfiledata, FileDataEntryFinal.Hmacfiledata) {

			err = errors.New("Chunk corrupted maliciously has been corrupted maliciously")
			return nil, err

		}
		//-------decrypting the encrypted chunk content

		filedataencryptedbytes := FileDataEntryFinal.Filedataencryptedbytes
		ivd := filedataencryptedbytes[:userlib.BlockSize]
		filedataencryptedbytes = filedataencryptedbytes[userlib.BlockSize:]
		streamd := userlib.CFBDecrypter(fileencryptionkeyatindex, ivd)
		streamd.XORKeyStream(filedataencryptedbytes, filedataencryptedbytes)

		// append decrypted chunk content to data array

		data = append(data[:], filedataencryptedbytes[:]...)
	}

	return data, err

}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	Fileencryptionkeys string
	FileindexLocation  []byte
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	msgid string, err error) {

	userdata.synchuser()
	var sharingstruct sharingRecord
	err = nil
	var fileencryptionkey string
	var locationofindextable string
	var present bool
	fileencryptionkey, present = userdata.Ownedfilekeysmap[filename]

	if present {
		temp := userlib.Argon2Key([]byte(userdata.Username+userdata.Password+filename), []byte{}, 16)

		locationofindextable = string(temp[:len(temp)])
	} else {
		sharedfileinfo, present := userdata.Sharedfileinfomap[filename]
		sharedfileinfoloc, present := userdata.Sharedfileinfomaploc[filename]
		if present {

			locationofindextable = string(sharedfileinfoloc)
			fileencryptionkey = sharedfileinfo

		} else {
			err = errors.New("filename not found")
			return "", err
		}

	}

	sharingstruct.Fileencryptionkeys = fileencryptionkey
	sharingstruct.FileindexLocation = []byte(locationofindextable) //check

	sharingstructbytes, err := json.Marshal(sharingstruct)

	if err != nil {
		return "", err
	}

	//encrypt sharingstruct bytes and sign and then senf

	recipientpublickey, okpresent := userlib.KeystoreGet(recipient)
	if !okpresent {
		err = errors.New("recipient public key not found")
		return "", err
	}

	msgenc, err := userlib.RSAEncrypt(&recipientpublickey, sharingstructbytes, []byte{})

	if err != nil {
		return "", err
	}
	sign, err := userlib.RSASign(userdata.PvtkeyRsa, msgenc)
	if err != nil {
		return "", err
	}

	type packet struct {
		Msgenc []byte
		Sign   []byte
	}

	var pu1send packet
	pu1send.Msgenc = msgenc
	pu1send.Sign = sign

	pu1sendbytes, err := json.Marshal(pu1send)
	if err != nil {
		return "", err
	}
	sharing := string(pu1sendbytes)

	err = nil

	return sharing, err
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {

	userdata.synchuser()

	var err error
	err = nil

	senderpublickey, okpresent := userlib.KeystoreGet(sender)

	if !okpresent {
		err = errors.New("Sender public key not found")
		return err

	}

	//verify recvd data
	msgidbytes := []byte(msgid)

	type packet struct {
		Msgenc []byte
		Sign   []byte
	}

	var pu2recv packet

	err = json.Unmarshal(msgidbytes, &pu2recv)

	if err != nil {
		return err
	}

	err = userlib.RSAVerify(&senderpublickey, pu2recv.Msgenc, pu2recv.Sign)

	if err != nil {
		return err
	} else {
		msgdec, err := userlib.RSADecrypt(userdata.PvtkeyRsa, pu2recv.Msgenc, []byte{})
		if err != nil {
			return err
		}

		var sharedfileinfo [2]string

		var sharedinfo sharingRecord

		err = json.Unmarshal(msgdec, &sharedinfo)
		if err != nil {
			return err
		}
		sharedfileinfo[0] = sharedinfo.Fileencryptionkeys
		sharedfileinfo[1] = string(sharedinfo.FileindexLocation[:len(sharedinfo.FileindexLocation)]) //check

		userdata.Sharedfileinfomap[filename] = sharedfileinfo[0] //updating the list
		userdata.Sharedfileinfomaploc[filename] = []byte(sharedfileinfo[1])

		_, okpresent = userdata.Ownedfilekeysmap[filename]
		if okpresent {
			delete(userdata.Ownedfilekeysmap, filename) // removing duplicates

		}

		userdata.updateuser()

	}

	return err
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	userdata.synchuser()

	totaldata, err := userdata.LoadFile(filename)

	userdata.StoreFileduringrevoke(filename, totaldata)

	return err
}

func (userdata *User) updateuser() {

	bigkey := userlib.Argon2Key([]byte(userdata.Username+userdata.Password), []byte{}, 32)

	newuserhash := bigkey[0 : len(bigkey)/2]

	userdatastorekeysymm := bigkey[len(bigkey)/2 : len(bigkey)]

	userdatabytes, _ := json.Marshal(userdata)

	userlib.DatastoreDelete(string(newuserhash))

	userdataencryptedbytes := make([]byte, userlib.BlockSize+len(userdatabytes)) //needs to be stored

	ivt := userlib.RandomBytes(userlib.BlockSize)
	for i := 0; i < userlib.BlockSize; i++ {
		userdataencryptedbytes[i] = ivt[i] //filling with random iv
	}

	iv := userdataencryptedbytes[:userlib.BlockSize]
	stream := userlib.CFBEncrypter(userdatastorekeysymm, iv)
	stream.XORKeyStream(userdataencryptedbytes[userlib.BlockSize:], userdatabytes)

	//-------calculate MAC--------
	hmac := userlib.NewHMAC(userdatastorekeysymm)
	hmac.Write(userdataencryptedbytes)

	hmacuserdata := hmac.Sum(nil) //needt to be stored

	type UserEntryFinalType struct {
		Userdataencryptedbytes []byte
		Hmacuserdata           []byte
	}

	var UserEntryFinal UserEntryFinalType
	UserEntryFinal.Hmacuserdata = hmacuserdata
	UserEntryFinal.Userdataencryptedbytes = userdataencryptedbytes

	UserEntryFinalbytes, _ := json.Marshal(UserEntryFinal)

	userlib.DatastoreSet(string(newuserhash), UserEntryFinalbytes)

}

func convert(n int) string {
	str := ""
	if n == 0 {

		str = "0"
		return str
	}

	for n != 0 {

		rem := n%10 + 48
		n = n / 10
		str = string(rem) + str

	}

	return str

}

func (userdata *User) synchuser() error {

	var updateusernew *User

	var err error

	updateusernew, err = GetUser(userdata.Username, userdata.Password)

	userdata.Username = updateusernew.Username
	userdata.Password = updateusernew.Password
	userdata.PvtkeyRsa = updateusernew.PvtkeyRsa
	userdata.Ownedfilekeysmap = updateusernew.Ownedfilekeysmap
	userdata.Sharedfileinfomap = updateusernew.Sharedfileinfomap

	return err

}

func (userdata *User) StoreFileduringrevoke(filename string, data []byte) {
	//userdata.synchuser()

	filedatastorekeysymmstring := uuid.New().String()

	filedatastorekeysymm := ([]byte(filedatastorekeysymmstring + "0"))[0:userlib.AESKeySize]
	var indextable []string //uc

	// encrypting the contents of the file

	filedataencryptedbytes := make([]byte, userlib.BlockSize+len(data)) //needs to be stored

	ivt := userlib.RandomBytes(userlib.BlockSize)
	for i := 0; i < userlib.BlockSize; i++ {
		filedataencryptedbytes[i] = ivt[i] //filling with random iv
	}

	iv := filedataencryptedbytes[:userlib.BlockSize]
	stream := userlib.CFBEncrypter(filedatastorekeysymm, iv)
	stream.XORKeyStream(filedataencryptedbytes[userlib.BlockSize:], data)

	//-------calculate MAC of the file encrypted contents--------
	hmac := userlib.NewHMAC(filedatastorekeysymm)
	hmac.Write(filedataencryptedbytes)

	hmacfiledata := hmac.Sum(nil) //needt to be stored

	type FileDataEntryFinalType struct {
		Filedataencryptedbytes []byte
		Hmacfiledata           []byte
	}

	var FileDataEntryFinal FileDataEntryFinalType
	FileDataEntryFinal.Hmacfiledata = hmacfiledata
	FileDataEntryFinal.Filedataencryptedbytes = filedataencryptedbytes

	FileDataEntryFinalbytes, _ := json.Marshal(FileDataEntryFinal) //uc

	// calculating the location of the chunk

	locationofchunk := string(userlib.Argon2Key([]byte(userdata.Username+userdata.Password+filename+"0"), []byte{}, 16))

	//adding entry to the index table

	indextable = append(indextable, locationofchunk)
	indextablebytes, _ := json.Marshal(indextable) //check

	var indextable2 []string
	json.Unmarshal(indextablebytes, &indextable2)
	userlib.DatastoreSet(indextable2[0], FileDataEntryFinalbytes)

	// encrypting the index table
	fileindexstorekeysymm := ([]byte(filedatastorekeysymmstring))[0:userlib.AESKeySize]

	fileindexencryptedbytes := make([]byte, userlib.BlockSize+len(indextablebytes)) //needs to be stored

	ivt = userlib.RandomBytes(userlib.BlockSize)
	for i := 0; i < userlib.BlockSize; i++ {
		fileindexencryptedbytes[i] = ivt[i] //filling with random iv
	}

	iv = fileindexencryptedbytes[:userlib.BlockSize]
	stream = userlib.CFBEncrypter(fileindexstorekeysymm, iv)
	stream.XORKeyStream(fileindexencryptedbytes[userlib.BlockSize:], indextablebytes)

	//-------calculate MAC of the index encrypted contents--------
	hmac = userlib.NewHMAC(fileindexstorekeysymm)
	hmac.Write(fileindexencryptedbytes)

	hmacindexdata := hmac.Sum(nil) //needt to be stored

	type FileIndexEntryFinalType struct {
		Fileindexencryptedbytes []byte
		Hmacindexdata           []byte
	}

	var FileIndexEntryFinal FileIndexEntryFinalType
	FileIndexEntryFinal.Hmacindexdata = hmacindexdata
	FileIndexEntryFinal.Fileindexencryptedbytes = fileindexencryptedbytes

	FileIndexEntryFinalBytes, _ := json.Marshal(FileIndexEntryFinal)

	// calculating the location of the indextable

	locationofindextable := string(userlib.Argon2Key([]byte(userdata.Username+userdata.Password+filename), []byte{}, 16))

	userlib.DatastoreSet(locationofindextable, FileIndexEntryFinalBytes)

	// updating the user map comprising the ownedmapkeysarray

	userdata.Ownedfilekeysmap[filename] = filedatastorekeysymmstring

	// -------------------------updating the map in the datastore-----------------------------

	userdata.updateuser()

}
