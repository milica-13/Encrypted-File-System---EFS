from user import User
from certificate_authority import CertificateAuthority
from directory_manager import *
import os
import getpass  

def main():
    logged_in_user = None  

    while True:
        print("\n--- SISTEM ZA UPRAVLJANJE SERTIFIKATIMA ---")
        print("1. Kreiraj CA")
        print("2. Registruj korisnika")
        print("3. Prijavi korisnika")
        if logged_in_user:  
            print("4. Rad sa folderima i fajlovima")
        print("5. Poništi pristup korisniku")
        print("6. Prikaži crl listu")
        print("7. Kraj rada...")
         

        izbor = input("Izaberite opciju: ")

        if izbor == "1":
            CertificateAuthority.create_ca()

        elif izbor == "2":
            username = input("Unesite korisničko ime: ")
            password = getpass.getpass("Unesite lozinku: ")  
            User.register_user(username, password)

        elif izbor == "3":
            username = input("Unesite korisničko ime: ")
            password = getpass.getpass("Unesite lozinku: ") 
            if User.login(username, password):
                #print(f"✅ Korisnik {username} je uspješno prijavljen.")
                logged_in_user = username  
            else:
                print("❌ Neuspješna prijava!")

        elif izbor == "4" and logged_in_user:
            manage_files(logged_in_user)  
        
        elif izbor == "5":
            ime = input("Unesite korisnicko ime osobe kojoj zelite povuci sertifikat: ")
            CertificateAuthority.test_revoke(ime)

        elif izbor == "6":
            CertificateAuthority.show_crl()

        elif izbor == "7":
            print("👋 Izlazak iz sistema...")
            break

        else:
            print("❌ Nepoznata opcija! Pokušajte ponovo.")


def manage_files(username):
    while True:
        print("\n--- UPRAVLJANJE FAJLOVIMA ---")
        print("1. Kreiraj tekstualni fajl")
        print("2. Kreiraj PDF fajl")
        print("3. Sačuvaj sliku")
        print("4. Prikaži fajlove")
        print("5. Obriši fajl")
        print("6. Kreiraj direktorijum")
        print("7. Obriši direktorijum")
        print("8. Pročitaj fajl")  
        print("9. Prenesi fajl na EFS (upload)")
        print("10. Preuzmi fajl sa EFS-a (download)")
        print("11. Podijeli fajl sa korisnikom")
        print("12. Preuzmi dijeljeni fajl")
        print("13. Odjava korisnika")
        print("14. Nazad")
        #print("15. Pročitaj preuzeti fajl (verifikovan)")


        opcija = input("Izaberite opciju: ")

        if opcija == "1":
            filename = input("Unesite naziv fajla: ")
            content = input("Unesite sadržaj fajla: ")
            create_txt_file(username, filename, content)

            """ if opcija == "1":
            filename = input("Unesite naziv fajla: ")
            content = input("Unesite sadržaj fajla: ")
            create_txt_file(username, filename, content) """
        
        elif opcija == "2":
            filename = input("Unesite naziv PDF fajla: ")
            content = input("Unesite sadržaj PDF fajla: ")
            create_pdf_file(username, filename, content)
        
        elif opcija == "3":
            filename = input("Unesite naziv slike (sa ekstenzijom): ")
            print("(Za sada, slika mora biti poslana kao bajt podaci)")
        
        elif opcija == "4":
            list_user_files(username)
        
        elif opcija == "5":
            filename = input("Unesite naziv fajla za brisanje: ")
            delete_file(username, filename)
        
        elif opcija == "6":
            dir_name = input("Unesite naziv direktorijuma: ")
            create_directory(username, dir_name)
        
        elif opcija == "7":
            dir_name = input("Unesite naziv direktorijuma za brisanje: ")
            delete_directory(username, dir_name)

        elif opcija == "8":
            filename = input("Unesite naziv fajla za čitanje: ")
            file_extension = os.path.splitext(filename)[1].lower()

            if file_extension == ".txt" or "." not in filename:
                #password = input("Unesite lozinku za dekripciju fajla: ")
                read_txt_file(username, filename)  # Dodajemo password
            elif file_extension == ".pdf":
                read_pdf_file(username, filename)
            else:
                print("Nepodržan format fajla! Samo .txt i .pdf fajlovi su podržani.")

        elif opcija == "9":
            local_path = input("Unesite putanju do fajla na host sistemu: ")
            efs_path = input("Unesite putanju gde će fajl biti sačuvan na EFS: ")
            upload_file(username, local_path, efs_path)

        elif opcija == "10":
            efs_path = input("Unesite putanju do fajla na EFS: ")
            local_path = input("Unesite putanju gde će fajl biti sačuvan na host sistemu: ")
            download_file(username, efs_path, local_path)

        elif opcija == "11":
            shared_username = input("Unesite ime korisnika sa kojim zelite da podijelite fajl: ")
            filename = input("Unesite ime fajla: ")
            share_file(username, shared_username, filename)

        elif opcija == "12":
            filename = input("Unesite ime fajla koji želite preuzeti: ")
            retrieve_shared_file(username, filename)
            


        elif opcija == "13":
            User.logout()
            break

        elif opcija == "14":
            break
        
        elif opcija == "15":
            sender_username=input("Unesite ime posiljaoca: ")
            filename= input("Naziv fajla koji zelite procitati: ")
            safe_read_shared_file(sender_username, username, filename)

        else:
            print("Nepoznata opcija! Pokušajte ponovo.")

if __name__ == "__main__":
    main()




# while True:
#                 print("\n--- UPRAVLJANJE FAJLOVIMA ---")
#                 print("1. Kreiraj tekstualni fajl")
#                 print("2. Kreiraj PDF fajl")
#                 print("3. Sačuvaj sliku")
#                 print("4. Prikaži fajlove")
#                 print("5. Obriši fajl")
#                 print("6. Kreiraj direktorijum")
#                 print("7. Obriši direktorijum")
#                 print("8. Pročitaj fajl")  
#                 print("9. Prenesi fajl na EFS (upload)")
#                 print("10. Preuzmi fajl sa EFS-a (download)")
#                 print("11. Podijeli fajl sa korisnikom")
#                 print("12. Preuzmi dijeljeni fajl")
#                 print("13. Nazad")
        
#                 opcija = input("Izaberite opciju: ")
        
#                 if opcija == "1":
#                     filename = input("Unesite naziv fajla: ")
#                     content = input("Unesite sadržaj fajla: ")
#                     create_txt_file(username, filename, content)
        
#                 elif opcija == "2":
#                     filename = input("Unesite naziv PDF fajla: ")
#                     content = input("Unesite sadržaj PDF fajla: ")
#                     create_pdf_file(username, filename, content)
        
#                 elif opcija == "3":
#                     filename = input("Unesite naziv slike (sa ekstenzijom): ")
#                     print("(Za sada, slika mora biti poslana kao bajt podaci)")
        
#                 elif opcija == "4":
#                     list_user_files(username)
        
#                 elif opcija == "5":
#                     filename = input("Unesite naziv fajla za brisanje: ")
#                     delete_file(username, filename)
        
#                 elif opcija == "6":
#                     dir_name = input("Unesite naziv direktorijuma: ")
#                     create_directory(username, dir_name)
        
#                 elif opcija == "7":
#                     dir_name = input("Unesite naziv direktorijuma za brisanje: ")
#                     delete_directory(username, dir_name)

#                 elif opcija == "8":  
#                     filename = input("Unesite naziv fajla za čitanje: ")
#                     file_extension = os.path.splitext(filename)[1].lower()

#                     if file_extension == ".txt" or "." not in filename:
#                         read_txt_file(username, filename)
#                     elif file_extension == ".pdf":
#                         read_pdf_file(username, filename)
#                     else:
#                         print("Nepodržan format fajla! Samo .txt i .pdf fajlovi su podržani.")

#                 elif opcija == "9":
#                     local_path = input("Unesite putanju do fajla na host sistemu: ")
#                     efs_path = input("Unesite putanju gde će fajl biti sačuvan na EFS: ")
#                     upload_file(username, local_path, efs_path)

#                 elif opcija == "10":
#                     efs_path = input("Unesite putanju do fajla na EFS: ")
#                     local_path = input("Unesite putanju gde će fajl biti sačuvan na host sistemu: ")
#                     download_file(username, efs_path, local_path)

#                 elif opcija == "11":
#                     shared_username = input("Unesite ime korisnika sa kojim zelite da podijelite fajl: ")
#                     filename = input("Unesite ime fajla: ")
#                     share_file(username, shared_username, filename)

#                 elif opcija == "12":
#                     filename = input("Unesite ime fajla koji želite preuzeti: ")
#                     retrieve_shared_file(username, filename)


#                 elif opcija == "13":
#                     break
        
#                 else:
#                     print("Nepoznata opcija! Pokušajte ponovo.")