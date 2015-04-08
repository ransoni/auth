package auth

import (
	"fmt"
	"log"
	"github.com/mavricknz/ldap"
)

var (
	server string = "192.168.15.11"
	port   uint16 = 389
	base_dn     string = "dc=lemonitor,dc=local"
	attributes []string = []string{
		"givenName",
		"sn",
		"mail",
		"cn",
		//		"distinguishedName",
		"memberOf",
		//		"description",
		"company"}

	fn		string = ""
	email	string = ""
	org		string = ""
	role	string = ""
	)

func none(u, p string) (*User, error) {
	return &User{}, nil
}

func simple(u, p string) (*User, error) {
	fmt.Println("ALARMAA!! \nsimple in drivers.go")
	if u == user && p == pass {
		return &User{ID: 0, Username: u, FullName: u, PasswordHash: "", PasswordSalt: "", Role: "operator"}, nil
	}
	return &User{}, fmt.Errorf("invalid user '%s' or invalid password", u)
}

func ldappi(u, p string) (*User, error) {
	fmt.Println("ALARMAA!! \nLDAP in drivers.go")
	fmt.Printf("User: %s, Pass: %s", u, p)
//	fmt.Printf("\nConf dumppi: %s", )

	fmt.Printf("TestConnect: starting...\n")
	l := ldap.NewLDAPConnection(server, port)
	//	l.Debug = true
	err := l.Connect()
	if err != nil {
		log.Printf("Error: %s\n", err.Error())
		//return
	} else {
		log.Printf("Did it work?\n")
		log.Printf("Connection: %s\n", l)
	}

	fmt.Printf("Type: %T\n", *l)

	u += "@lemonitor.local"

	errBind := l.Bind(u, p)
	if errBind != nil {
		log.Printf("Bind: %s\n", errBind.Error())
	} else {
		log.Printf("Bind worked!\n")
		fmt.Println("Bind:", errBind)

//	OMIEN TIETOJEN HAKU
		fltr := "(&(objectClass=person)(userPrincipalName="
		fltr += u
		fltr += ")"
		fmt.Println("Fltr:", fltr)

		if err == nil {
			search_request := ldap.NewSearchRequest(
				base_dn,
				ldap.ScopeWholeSubtree, ldap.DerefInSearching, 0, 0, false, //CHANGE: ldap.DerefAlways -> ldap.NeverDerefAliases
				fltr,
				attributes,
				nil)

			sr, err := l.Search(search_request)
			if err != nil {
				log.Printf(err.Error())
				//return
			}

			for i := range sr.Entries {
				//if

				fmt.Println(sr.Entries[i])
				fmt.Println(sr.Entries[i].Attributes[0].Name, "Length:", len(sr.Entries[i].Attributes))
				for key, value := range sr.Entries[i].Attributes {

					fmt.Printf("\nKey: %v Name: %s Values(%v): %v", key, value.Name, len(value.Values), value.Values[0])

					switch {
					case value.Name == "cn":
						fn = value.Values[0]
						fmt.Println("case cn:", value.Values[0])
					case value.Name == "mail":
						email = value.Values[0]
						fmt.Println("case email:", value.Values[0])
					case value.Name == "company":
						org = value.Values[0]
						fmt.Println("case company:", value.Values[0])
					case value.Name == "memberOf":
						role = value.Values[0]
						fmt.Println("case role:", value.Values[0])

					}

				}

			}
		}

		defer l.Close()

// TIETOJEN HAKU PÄÄTTYY
	/* USER INFO MAPPINGS
		struct = ldap attribute
		ID = ??
		Username = u
		FullName = givenName + sn || cn
		Email = mail
		Organization = company
		Role = memberOf

	 */

		return &User{ID: 0, Username: u, FullName: fn, Email: email, PasswordHash: "", PasswordSalt: "", Role: "operator", Org: org}, nil
	}

/*	if u == user && p == pass {
		return &User{ID: 0, Username: u, FullName: u, PasswordHash: "", PasswordSalt: "", Role: "operator"}, nil
	}
*/
	return &User{}, fmt.Errorf("invalid user '%s' or invalid password", u)
}

