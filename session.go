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

const (
    MESSAGE_TYPE_PRE_KEY = iota
    OLM_MESSAGE_TYPE_MESSAGE = iota
)

type Session struct {
    buf []byte
    ptr *C.struct_OlmSession
}

func newSession() (Session){
    session_buf := make([]byte, C.olm_session_size())
    fmt.Printf("Created buf at %p\n", session_buf)
    olm_session := C.olm_session(unsafe.Pointer(&session_buf[0]))
    fmt.Printf("New session: %#v at %v\n", olm_session, &olm_session)

    return Session{buf: session_buf, ptr: olm_session}
}

func CreateOutboundSession(
        account Account, their_identity_key string,
        their_one_time_key string) (Session){

    session := newSession()

    random_length := C.olm_create_outbound_session_random_length(session.ptr)
    random_buffer := make([]byte, random_length)

    _, err := rand.Read(random_buffer)

    if err != nil {
        // currently we panic when we don't have enough randomness but it
        // might be better to return an error instead. however I feel like
        // other programmers might not recognize what a huge issue not having
        // randomness is so I chose the crash and burn approach
        panic(err)
    }

    identity_key_buffer := []byte(their_identity_key)
    one_time_key_buffer := []byte(their_one_time_key)

    C.olm_create_outbound_session(
        session.ptr, account.ptr,
        unsafe.Pointer(&identity_key_buffer[0]),
        C.size_t(len(identity_key_buffer)),
        unsafe.Pointer(&one_time_key_buffer[0]),
        C.size_t(len(one_time_key_buffer)),
        unsafe.Pointer(&random_buffer[0]), random_length,
    )

    return session
}

func CreateInboundSession(account Account, one_time_key_message string)(Session){
    session := newSession()

    one_time_key_message_buffer := []byte(one_time_key_message)

    C.olm_create_inbound_session(
        session.ptr,
        account.ptr,
        unsafe.Pointer(&one_time_key_message_buffer[0]),
        C.size_t(len(one_time_key_message_buffer)),
    )

    return session
}

func CreateInboundSessionFrom(account Account, their_identity_key string,
        one_time_key_message string)(Session){

    session := newSession()

    one_time_key_message_buffer := []byte(one_time_key_message)

    C.olm_create_inbound_session(
        session.ptr,
        account.ptr,
        unsafe.Pointer(&one_time_key_message_buffer[0]),
        C.size_t(len(one_time_key_message_buffer)),
    )

    return session
}

func SessionFromPickle(key string, pickle string) (Session){
    session := newSession()

    key_buf := []byte(key)
    pickle_buffer := []byte(pickle)

    // this returns a result we should probably inspect
    C.olm_unpickle_session(
        session.ptr,
        unsafe.Pointer(&key_buf[0]), C.size_t(len(key_buf)),
        unsafe.Pointer(&pickle_buffer[0]), C.size_t(len(pickle_buffer)),
    )

    fmt.Println(session.lastError())

    return session
}

func (s Session) lastError() (string){
    return C.GoString(C.olm_session_last_error(s.ptr))
}

func (s Session) Pickle(key string) (string){
    key_buf := []byte(key)
    pickle_buffer := make([]byte, C.olm_pickle_session_length(s.ptr))

    // this returns a result we should probably inspect
    C.olm_pickle_session(
        s.ptr,
        unsafe.Pointer(&key_buf[0]), C.size_t(len(key_buf)),
        unsafe.Pointer(&pickle_buffer[0]), C.size_t(len(pickle_buffer)),
    )

    return string(pickle_buffer)
}

func (s Session) GetSessionID() {
    id_length := C.olm_session_id_length(s.ptr)
    id_buffer := make([]byte, id_length)
    C.olm_session_id(s.ptr, unsafe.Pointer(&id_buffer[0]), id_length)
}

func (s Session) Encrypt(plaintext string) (int, string){
    random_length := C.olm_encrypt_random_length(s.ptr)
    random_buffer := []byte{0}
    
    if random_length > 0 {
        random_buffer = make([]byte, random_length)

        _, err := rand.Read(random_buffer)

        if err != nil {
            // currently we panic when we don't have enough randomness but it might
            // be better to return an error instead. however I feel like other
            // programmers might not recognize what a huge issue not having
            // randomness is so I chose the crash and burn approach
            panic(err)
        }
    }
    
    plaintext_buffer := []byte(plaintext)
    
    message_type := C.olm_encrypt_message_type(s.ptr)
    message_length := C.olm_encrypt_message_length(
        s.ptr, C.size_t(len(plaintext_buffer)),
    )
    message_buffer := make([]byte, message_length)

    C.olm_encrypt(
        s.ptr,
        unsafe.Pointer(&plaintext_buffer[0]),
        C.size_t(len(plaintext_buffer)),
        unsafe.Pointer(&random_buffer[0]), random_length,
        unsafe.Pointer(&message_buffer[0]), message_length,
    )

    return int(message_type), string(message_buffer)
}

func (s Session) Decrypt(message_type int, message string) (string) {
    message_buffer := []byte(message)
    max_plaintext_length := C.olm_decrypt_max_plaintext_length(
        s.ptr, C.size_t(message_type),
        unsafe.Pointer(&message_buffer[0]), C.size_t(len(message_buffer)),
    )
    
    message_buffer = []byte(message)
    plaintext_buffer := make([]byte, max_plaintext_length)
    plaintext_length := C.olm_decrypt(
        s.ptr, C.size_t(message_type),
        unsafe.Pointer(&message_buffer[0]), C.size_t(len(message_buffer)),
        unsafe.Pointer(&plaintext_buffer[0]), max_plaintext_length,
    )

    return string(plaintext_buffer[:plaintext_length])
}

func (s Session) matches_inbound(one_time_key_message string) (bool){
    one_time_key_message_buffer := []byte(one_time_key_message)

    result := C.olm_matches_inbound_session(
        s.ptr,
        unsafe.Pointer(&one_time_key_message_buffer[0]),
        C.size_t(len(one_time_key_message_buffer)),
    )

    return result != 0
}

func (s Session) matches_inbound_from(
        their_identity_key string, one_time_key_message string) (bool){
    identity_key_buffer := []byte(their_identity_key)
    one_time_key_message_buffer := []byte(one_time_key_message)

    result := C.olm_matches_inbound_session_from(
        s.ptr,
        unsafe.Pointer(&identity_key_buffer[0]),
        C.size_t(len(identity_key_buffer)),
        unsafe.Pointer(&one_time_key_message_buffer[0]),
        C.size_t(len(one_time_key_message_buffer)),
    )

    return result != 0
}
