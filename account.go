package libolm-go

/*
#cgo LDFLAGS: -lolm
#include <olm/olm.h>
#include <stdlib.h>
*/
import "C"

import (
    //"encoding/json"
    "fmt"
    "crypto/rand"
    "unsafe"
)

func GetVersion() (major byte, minor byte, patch byte){
    var ma C.uint8_t
    var mi C.uint8_t
    var pa C.uint8_t
    C.olm_get_library_version(&ma, &mi, &pa)
    return byte(ma), byte(mi), byte(pa)
}

type Account struct {
    buf []byte
    ptr *C.struct_OlmAccount
}

func AccountFromPickle(key string, pickle string) (Account){
    account := newAccount()

    key_buf := []byte(key)
    pickle_buffer := []byte(pickle)

    // this returns a result we should probably inspect
    C.olm_unpickle_account(
        account.ptr,
        unsafe.Pointer(&key_buf[0]), C.size_t(len(key_buf)),
        unsafe.Pointer(&pickle_buffer[0]), C.size_t(len(pickle_buffer)),
    )

    fmt.Println(account.lastError())

    return account
}

func newAccount() (Account){
    account_buf := make([]byte, C.olm_account_size())
    olm_account := C.olm_account(unsafe.Pointer(&account_buf[0]))

    return Account{buf: account_buf, ptr: olm_account}
}

func CreateNewAccount() (Account){
    account := newAccount()
    rand_len := C.olm_create_account_random_length(account.ptr)
    rand_buf := make([]byte, rand_len)

    _, err := rand.Read(rand_buf)

    if err != nil {
        // currently we panic when we don't have enough randomness but it might
        // be better to return an error instead. however I feel like other
        // programmers might not recognize what a huge issue not having
        // randomness is so I chose the crash and burn approach
        panic(err)
    }

    fmt.Println(account.lastError())

    C.olm_create_account(account.ptr, unsafe.Pointer(&rand_buf[0]), rand_len)

    return account
}

func (a Account) lastError() (string){
    return C.GoString(C.olm_account_last_error(a.ptr))
}

func (a Account) Pickle(key string) (string){
    key_buf := []byte(key)
    pickle_buffer := make([]byte, C.olm_pickle_account_length(a.ptr))

    // this returns a result we should probably inspect
    C.olm_pickle_account(
        a.ptr,
        unsafe.Pointer(&key_buf[0]), C.size_t(len(key_buf)),
        unsafe.Pointer(&pickle_buffer[0]), C.size_t(len(pickle_buffer)),
    )

    return string(pickle_buffer)
}

func (a Account) GetIdentityKeys() (string){
    out_length := C.olm_account_identity_keys_length(a.ptr)
    out_buffer := make([]byte, out_length)
    C.olm_account_identity_keys(
        a.ptr,
        unsafe.Pointer(&out_buffer[0]), out_length,
    )
    // JSON, could parse
    return string(out_buffer)
}

func (a Account) Sign(message string) (string){
    message_buf := []byte(message)
    out_length := C.olm_account_signature_length(a.ptr)
    out_buffer := make([]byte, out_length)
    C.olm_account_sign(
        a.ptr,
        unsafe.Pointer(&message_buf[0]), C.size_t(len(message_buf)),
        unsafe.Pointer(&out_buffer[0]), out_length,
    )
    return string(out_buffer)
}

func (a Account) GetOneTimeKeys() (string){
    out_length := C.olm_account_one_time_keys_length(a.ptr)
    out_buffer := make([]byte, out_length)
    C.olm_account_one_time_keys(
        a.ptr,
        unsafe.Pointer(&out_buffer[0]), out_length,
    )
    // JSON, could parse
    return string(out_buffer)
}

func (a Account) MarkKeysAsPublished() {
    C.olm_account_mark_keys_as_published(a.ptr)
}

func (a Account) GetMaxNumberOfOneTimeKeys() (int){
    return int(C.olm_account_mark_keys_as_published(a.ptr))
}

func (a Account) GenerateOneTimeKeys(count int){
    rand_len := C.olm_account_generate_one_time_keys_random_length(
        a.ptr, C.size_t(count),
    )
    rand_buf := make([]byte, rand_len)

    _, err := rand.Read(rand_buf)

    if err != nil {
        // currently we panic when we don't have enough randomness but it might
        // be better to return an error instead. however I feel like other
        // programmers might not recognize what a huge issue not having
        // randomness is so I chose the crash and burn approach
        panic(err)
    }


    C.olm_account_generate_one_time_keys(
        a.ptr, C.size_t(count),
        unsafe.Pointer(&rand_buf[0]), rand_len,
    )

    fmt.Println(a.lastError())
}
