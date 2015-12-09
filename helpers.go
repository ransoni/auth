package auth

import (
	"fmt"
	"log"

	"crypto/tls"
	"github.com/go-ldap/ldap"
//	"github.com/mavricknz/ldap"
)

var (
//	server string = "192.168.15.110"
//	port   uint16 = 636
//	base_dn     string = "dc=monni,dc=local"
	ldapuser	  string   = "ldapauth"
	ldappass	  string   = "authbind998"
/*	attributes []string = []string{
		"givenName",
		"sn",
		"mail",
		"uid",
		"ou",
		"dn",
		"cn",
		//		"distinguishedName",
		"memberOf",
		"mepManagedBy",
		"krbLastSuccessfulAuth",
		//		"description",
		//		"company"
	}

	fn		string = ""
	email	string = ""
	org		string = ""
	role	string = "" */
	)

func getUserInfo(t, e string) (*User, error) {
//	t = tenant, e = email
	fmt.Printf("Tenant: %s\nUser: %s", t, e)

//	Configure TLS connection parameters
	config := tls.Config{InsecureSkipVerify: true}

	fmt.Printf("TestConnect: starting...\n")
	l, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", server, port), &config)
	//	l.Debug = true
	if err != nil {
		log.Printf("Error: %s\n", err.Error())
		//return
	} else {
		log.Printf("Connected: %s\n", l)
	}

//	unp := "mail=" + e + ",cn=users,cn=accounts,dc=monni,dc=local" // FreeIPA without RDN

	errBind := l.Bind(ldapuser, ldappass)
	if errBind != nil {
		log.Printf("Bind error: %s\n", errBind.Error())
		return nil, errBind
	} else {
		log.Printf("Bind worked!\n")
	}

//	START USER SEARCH
	//	Search the user
//	fltr := "(&(objectClass=person)(|(uid=*" + u + "*)(sn=" + u + ")(givenname=*" + u + "*)(mail=*" + u + "*)))"
	fltr := "(&(objectClass=person)(&(mail=" + e + ")(ou=" + t + "))"
	//fltr := "(&(objectClass=user)(sAMAccountName=*)(memberOf=CN=*,OU=*,DC=*,DC=*))"
	//	fmt.Println("Fltr:", fltr)

	if err == nil {
		search_request := ldap.NewSearchRequest(
		base_dn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, //CHANGE: ldap.DerefAlways -> ldap.NeverDerefAliases
		fltr,
		attributes,
		nil)

		_, err := l.Search(search_request)
		if err != nil {
			log.Printf(err.Error())
//			return dn, err
		}

/*
		if len(sr.Entries) == 1 {
			dn = sr.Entries[0].DN
		} else {
			l.Close()
			return dn, err
		}
*/

//		for i := range sr.Entries {
////			fmt.Printf("\nENTRY NRO: %v\nDN: %v\n------------------------\n", i+1, sr.Entries[i].DN)
//			for key, value := range sr.Entries[i].Attributes {
//				//		fmt.Println("Key: ", key, "Value: ", value)
//				if debug {
//					fmt.Printf("   Key: %v Name: %s Values(%v): ", key, value.Name, len(value.Values))
//				}
//				for i := range value.Values {
//					if i > 0 {
//						fmt.Printf("                                 ")
//					}
//					fmt.Println(value.Values[i])
//				}
//			}
//		}
	}
	l.Close()
//	END OF USER SEARCH

	return &User{ID: 0, Username: e, FullName: fn, Email: email, PasswordHash: "", PasswordSalt: "", Role: "operator", Org: org}, nil

//	return &User{}, fmt.Errorf("invalid user '%s' or invalid password", e)
}

