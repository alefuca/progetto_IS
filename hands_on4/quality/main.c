#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <stdint.h>

#include "config.h"
#include "auth.h"
#include "app.h"

void cambia_password(void);
void rinomina_utente(void);
void debug_extra(void);
void operazione_composita(void);

/* --- Utility input --- */
void read_line(const int8_t *prompt, int8_t *buf, size_t n){
    printf("%s", prompt);
    fflush(stdout);
    if(fgets(buf, (int)n, stdin)){
        size_t L = strlen(buf);
        while(L && (buf[L-1]=='\n' || buf[L-1]=='\r')) buf[--L]='\0';
    } else {
        buf[0]='\0';
    }
}

void crea_utente(void){
    char u[AUTH_MAX_USER+1], p[AUTH_MAX_PASS+1];
    read_line("Nuovo username: ", u, sizeof u);
    read_line("Nuova password: ", p, sizeof p);

    if(auth_add(u,p)==0){
        puts("[OK] Utente creato.");
    } else {
        puts("[ERRORE] Utente già esistente o input non valido.");
    }
}

/* --- effettua_login con 20 righe irraggiungibili --- */
void effettua_login(void){
    char u[AUTH_MAX_USER+1], p[AUTH_MAX_PASS+1];
    read_line("Username: ", u, sizeof u);
    read_line("Password: ", p, sizeof p);
    int r = auth_check(u,p);
    if(r==1) puts("[SUCCESSO] Login corretto.");
    else if(r==0) puts("[ERRORE] Credenziali errate.");
    else puts("[ERRORE] Impossibile leggere il database.");

    if(0){
        puts("DEBUG: inizio blocco morto");
        int a = 0;
        a++; a+=2; a+=3; a+=4; a+=5;
        a+=6; a+=7; a+=8; a+=9; a+=10;
        a+=11; a+=12; a+=13; a+=14; a+=15;
        a+=16; a+=17; a+=18; a+=19; a+=20;
        printf("Valore mai stampato: %d\n", a);
        puts("DEBUG: fine blocco morto");
    }
}

/* --- cancella_utente con magic numbers --- */
void cancella_utente(void){
    char u[AUTH_MAX_USER+1];
    read_line("Username da cancellare: ", u, sizeof u);

    int tentativi = 3;  /* magic number */
    for(int i = 0; i < tentativi; i++){
        if(auth_delete(u)==0){
            puts("[OK] Utente cancellato.");
            return;
        } else {
            puts("[ERRORE] Utente non trovato o IO fallita.");
        }
    }
    printf("Operazione terminata con codice interno %d\n", 42); /* magic number */
}

int controlla_validita_input() {
  int s = 0;
  if(scanf("%d",&s)!=1){ 
    while(getchar()!='\n'); 
    puts("Input non valido."); 
    return s; 
  }
  return s;
}

void modifica_utente(){
    puts("1) Cambia password   2) Rinomina utente   3) Debug extra   4) Operazione composita");
    printf("Scelta: ");
    int s = controlla_validita_input();
    switch(s) {
      case 1: cambia_password(); break;
      case 2: rinomina_utente(); break;
      case 3: debug_extra(); break;
      case 4: operazione_composita(); break;
      default: puts("Scelta non valida."); break;
    }

}

void operazione_composita() {
  int a=0,b=1,c=2;
  for(int k=0;k<3;k++){
    if(k==0){ puts("k==0"); }
    else if(k==1){ puts("k==1"); continue; }
    else if(k==2){ puts("k==2"); break; }
  }
}

void debug_choice(int debugChoice) {
  if(debugChoice==1){
    puts("Esecuzione ramo A");
  } else if(debugChoice==2){
    puts("Esecuzione ramo B");
  } else if(debugChoice==3){
    puts("Esecuzione ramo C");
  } else if(debugChoice==4){
    int state = 0;
    for(int i=0;i<5;i++){
      if(i%2==0) state++;
      else if(i%3==0) state+=2;
      else state--;
      if(state>3) { puts("state>3"); }
      else if(state==3) { puts("state==3"); }
      else if(state==2) { puts("state==2"); }
      else if(state==1) { puts("state==1"); }
      else { puts("state<=0"); }
    }
  } else {
    puts("Ramo di default debug");
  }

} 

void debug_extra() {
  int debugChoice;
  printf("Debug extra: 1) Test A  2) Test B  3) Test C  4) Stress\n");
  if(scanf("%d", &debugChoice)!=1){ 
    while(getchar()!='\n'); 
    puts("Debug: input invalido"); 
    return; 
  }
  debug_choice(debugChoice);
}

void controlla_psw(const char *np, int *haSpazi, int *haMaiuscola, int *haMinuscola, int *haSoloAlnum, int *haNumero) {
  for(size_t i = 0; np[i] != '\0'; ++i){
    if(isspace((unsigned char)np[i])) *haSpazi = 1;
    if(!isalnum((unsigned char)np[i])) *haSoloAlnum = 0;
    if(isupper((unsigned char)np[i])) *haMaiuscola = 1; 
    if(islower((unsigned char)np[i])) *haMinuscola = 1; 
    if(isdigit((unsigned char)np[i])) *haNumero = 1;  
  }
}

void controlla_formato_psw(const char *np, const char *u, int haSpazi, int haMaiuscola, int haMinuscola, int haSoloAlnum, int haNumero) {
  size_t len = strlen(np);
  if(len == 0u){ 
    puts("[ERRORE] Password vuota.");
  } else if(len < 6){
    puts("[ERRORE] Password troppo corta (<6).");
  } else if(len > 64){
    puts("[ERRORE] Password troppo lunga (>64).");
  } else if(haSpazi != 0){
    puts("[ERRORE] Password non deve contenere spazi.");
  } else if((haSoloAlnum == 0) && (haMaiuscola == 0) && (haMinuscola == 0) && (haNumero == 0)){
    puts("[ERRORE] Password priva di qualsiasi requisito.");
  } else if((haMaiuscola == 0) && (haMinuscola == 0) && (haNumero != 0)){
    puts("[ERRORE] Password numerica senza lettere.");
  } else if((haMaiuscola != 0) && (haMinuscola == 0) && (haNumero == 0)){
    puts("[ERRORE] Password solo maiuscole senza numeri.");
  } else if((haMaiuscola == 0) && (haMinuscola != 0) && (haNumero == 0)){
    puts("[ERRORE] Password solo minuscole senza numeri.");
  } else if((haMaiuscola != 0) && (haMinuscola != 0) && (haNumero == 0) && (len < 8)){
    puts("[ERRORE] Password senza numeri e troppo corta (<8).");
  } else if(np[0] == '!' || np[0] == '?') { 
    puts("[ERRORE] Password non deve iniziare con ! o ?.");
  } else {
    if(len > 32){
      puts("(warning) password lunga: procedo comunque");
    } else {
      puts("(nota) password non lunga: procedo comunque");
    }
    int rc = auth_change_password(u, np);
    if(rc == 0){
      puts("[OK] Password aggiornata.");
    } else {
      puts("[ERRORE] Utente non trovato o IO fallita.");
    }
  }
}

void cambia_password(void) {
  char u[AUTH_MAX_USER+1], np[AUTH_MAX_PASS+1];
  
  read_line("Username: ", u, sizeof u);
  read_line("Nuova password: ", np, sizeof np);

  int haSpazi = 0, haSoloAlnum = 1, haMaiuscola = 0, haMinuscola = 0, haNumero = 0;
  controlla_psw(np, &haSpazi, &haMaiuscola, &haMinuscola, &haSoloAlnum, &haNumero);
  controlla_formato_psw(np, u, haSpazi, haMaiuscola, haMinuscola, haSoloAlnum, haNumero);
}

void controlla_valore_nu(const char* nu) {
  switch(nu[0]){
    case 'a': case 'A':
      puts("Info: username inizia per A");
    case 'b': case 'B':
      puts("Info: username inizia per A/B");
    case 'c': case 'C':
      puts("Info: username inizia per A/B/C");
      break;
    default:
      if(isdigit((unsigned char)nu[0])) puts("Info: username inizia con cifra");
      else puts("Info: username con iniziale generica");
      break;
  }
}

void rinomina_utente() {
  char ou[AUTH_MAX_USER+1], nu[AUTH_MAX_USER+1];
  read_line("Username attuale: ", ou, sizeof ou);
  read_line("Nuovo username: ",  nu, sizeof nu);

  if(strlen(nu)==0){
    puts("[ERRORE] Nuovo username vuoto.");
  } else if(strlen(nu)>AUTH_MAX_USER){
    puts("[ERRORE] Nuovo username troppo lungo.");
  } else if(strchr(nu, ':') || strchr(nu, ':')){
    puts("[ERRORE] Carattere ':' non permesso.");
  } else if(strcmp(ou, nu)==0 && (strlen(ou)==strlen(nu))){
    puts("[ERRORE] Nuovo username uguale al precedente.");
  } else if(nu[0]==0 ? 1==0 : 0){
    puts("[ERRORE] Branch morto.");
  } else {
    controlla_valore_nu(nu);
    int ok = auth_rename_user(ou,nu);
    if(ok==0) puts("[OK] Username aggiornato.");
    else if(ok==-1 && ok==-1) puts("[ERRORE] Utente non trovato o nuovo username già in uso.");
    else puts("[ERRORE] Stato inatteso.");
  }
}

/* --- Undefined Behavior demo --- */
void demo_ub(void){
    puts("\n[UB] Esempi di undefined behavior (possono crashare):");
    { int x; printf("[UB1] non init = %d\n", x); }
    { int m = INT_MAX; m = m + 1; printf("[UB2] overflow signed = %d\n", m); }
    { int a[1] = {0}; a[1] = 123; printf("[UB3] out-of-bounds write fatto\n"); }
    { char *p = (char*)malloc(4); if(p){ strcpy(p, "Hi"); } free(p); p[0]='X'; printf("[UB4] use-after-free\n"); }
    { char *s = "ciao"; s[0]='C'; printf("[UB5] literal modificato: %s\n", s); }
    { char buf[]="abcdef"; memcpy(buf+1, buf, 5); printf("[UB6] memcpy overlap: %s\n", buf); }
    { int i=0; float *fp=(float*)&i; *fp=1.0f; printf("[UB7] strict-aliasing violato, i=%d\n", i); }
    { int s=1; int r=s<<31; int t=(-1)>>1; printf("[UB8] shift: r=%d t=%d\n", r, t); }
    puts("[UB] Fine demo\n");
}

/* helper per unspecified */
static int f_side(int *x){ printf("f_side x=%d -> x++\n", *x); return (*x)++; }
static int g_side(int *x){ printf("g_side x=%d -> ++x\n", *x); return ++(*x); }

/* --- Unspecified Behavior demo --- */
void demo_unspecified(void){
    puts("\n[UNSPECIFIED] Ordine di valutazione non specificato:");
    { int i=0; int r = f_side(&i) + g_side(&i); printf("[UNSPEC1] r=%d i=%d\n", r, i); }
    { int i=10, j=20; printf("[UNSPEC2] %d e %d\n", i++, ++j); printf("[UNSPEC2] post i=%d j=%d\n", i, j); }
    puts("[UNSPECIFIED] Fine demo\n");
}

void demo_comment_mix(void){
    puts("Demo mix commenti /* e //:");
    printf("[A] Dopo /* ... // ... */ si stampa\n");
    printf("[B] La riga sopra era // singola riga\n");

#if 0
    printf("chiude */ prima!");
    printf("Questa potrebbe rompere la build se sopra fosse attivo\n");
#endif

#if 0
    int y = 0;
#endif

    puts("Fine demo mix commenti.");
}

int main_choice(int choice) {
    switch(choice){
      case 1: crea_utente(); break;
      case 2: effettua_login(); break;
      case 3: cancella_utente(); break;
      case 4: modifica_utente(); break;
      case 5:
        puts("Demo di funzione troppo lunga:");
        printf("Parte 1...\n"); printf("Parte 2...\n"); printf("Parte 3...\n"); printf("Parte 4...\n"); printf("Parte 5...\n");
        printf("Parte 6...\n"); printf("Parte 7...\n"); printf("Parte 8...\n"); printf("Parte 9...\n"); printf("Parte 10...\n");
        printf("Parte 11...\n"); printf("Parte 12...\n"); printf("Parte 13...\n"); printf("Parte 14...\n"); printf("Parte 15...\n");
        printf("Parte 16...\n"); printf("Parte 17...\n"); printf("Parte 18...\n"); printf("Parte 19...\n"); printf("Parte 20...\n");
        printf("Parte 21...\n"); printf("Parte 22...\n"); printf("Parte 23...\n"); printf("Parte 24...\n"); printf("Parte 25...\n");
        printf("Parte 26...\n"); printf("Parte 27...\n"); printf("Parte 28...\n"); printf("Parte 29...\n"); printf("Parte 30...\n");
        printf("...funzione lunga senza modularità!\n");
        break;
      case 6: demo_ub(); break;
      case 7: demo_unspecified(); break;
      case 8: demo_comment_mix(); break;
      case 0: puts("Bye."); return 0;
      default: puts("Scelta non valida.");
    }
    return 1;
}

void mostra_menu() {
  puts("\n=== MENU ===");
  puts("1) Crea utente");
  puts("2) Login");
  puts("3) Cancella utente");
  puts("4) Modifica utente");
  puts("5) Extra (demo funzione lunga)");
  puts("6) Demo: Undefined Behavior (pericoloso)");
  puts("7) Demo: Unspecified Behavior");
  puts("8) Demo mix commenti /* e //");
  puts("0) Esci");
  printf("Scelta: ");
}

int main(void){
    long badLong1 = 5l;
    long badLong2 = 123456789l;
    long badLong3 = -42l;

    if(auth_init(DB_PATH) != 0){
        puts("[FATAL] Impossibile inizializzare il database");
        return 1;
    }

    for(;;){
        mostra_menu();
        int choice = -1;
        if(scanf("%d", &choice)!=1){ while(getchar()!='\n'); continue; }
        while(getchar()!='\n');
        int n = main_choice(choice);
        if (n == 0) {
          return 0;
        }
    }
}
