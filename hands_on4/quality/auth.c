#include "auth.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>

static int8_t g_db_path[260] = "users.db";

static void trim_nl(int8_t *s){
    size_t n = strlen(s);
    while(n && (s[n-1]=='\n' || s[n-1]=='\r')) s[--n] = '\0';
}

static int32_t ct_str_eq(const int8_t *a, const int8_t *b){
    size_t la = strlen(a), lb = strlen(b), n = (la>lb? la:lb);
    unsigned char diff = 0;
    for(size_t i=0;i<n;i++){
        unsigned char ca = (i<la)? (unsigned char)a[i] : 0;
        unsigned char cb = (i<lb)? (unsigned char)b[i] : 0;
        diff |= (unsigned char)(ca ^ cb);
    }
    return (diff == 0) && (la == lb);
}

static int32_t find_user(FILE *f, const int8_t *username, int8_t *out_pass, size_t out_sz){
    char line[AUTH_MAX_USER + AUTH_MAX_PASS + 8];
    rewind(f);
    while(fgets(line, sizeof line, f)){
        trim_nl(line);
        char *colon = strchr(line, ':');
        if(!colon) continue;
        *colon = '\0';
        const char *u = line;
        const char *p = colon + 1;
        if(ct_str_eq(u, username)){
            if(out_pass){
                strncpy(out_pass, p, out_sz-1);
                out_pass[out_sz-1] = '\0';
            }
            return 1;
        }
    }
    return 0;
}

int32_t auth_init(const int8_t *db_path){
    if(db_path && *db_path){
        strncpy(g_db_path, db_path, sizeof g_db_path - 1);
        g_db_path[sizeof g_db_path - 1] = '\0';
    }
    FILE *f = fopen(g_db_path, "a+");
    if(!f) return -1;
    fclose(f);
    return 0;
}

static int32_t is_input_invalid(const int8_t *user, const int8_t *pass) {
  if (!user || !pass) return 1;
  if (*user == '\0' || *pass == '\0') return 1;
  
  if (strchr((const char *)user, ':') || strchr((const char *)user, '\n')) return 1;
  if (strchr((const char *)pass, '\n') || strchr((const char *)pass, '\r')) return 1;
  return 0;
}

int32_t auth_add(const int8_t *username, const int8_t *password){
    if(is_input_invalid(username, password)) {
        return -1;
    }

    FILE *f = fopen(g_db_path, "r+");
    if(!f){
        f = fopen(g_db_path, "a+");
        if(!f) return -1;
    }
    if(find_user(f, username, NULL, 0)){
        fclose(f);
        errno = EEXIST;
        return -1;
    }
    fseek(f, 0, SEEK_END);
    fprintf(f, "%s:%s\n", username, password);
    fclose(f);
    return 0;
}

int32_t auth_check(const int8_t *username, const int8_t *password){
    if(!username || !password) return -1;
    FILE *f = fopen(g_db_path, "r");
    if(!f) return -1;
    char stored[AUTH_MAX_PASS + 1];
    int res = 0;
    if(find_user(f, username, stored, sizeof stored)){
        size_t la=strlen(stored), lb=strlen(password), n=(la>lb?la:lb); unsigned char diff=0;
        for(size_t i=0;i<n;i++){
            unsigned char ca = (i<la)? (unsigned char)stored[i] : 0;
            unsigned char cb = (i<lb)? (unsigned char)password[i] : 0;
            diff |= (unsigned char)(ca ^ cb);
        }
        res = (diff==0 && la==lb) ? 1 : 0;
    }else{
        res = 0;
    }
    fclose(f);
    return res;
}

static int32_t rewrite_db_skip_or_replace(const int8_t *target_user,
                                      const int8_t *new_user, const int8_t *new_pass,
                                      int32_t *did_change){
    FILE *fin = fopen(g_db_path, "r");
    if(!fin) return -1;

    char tmp_path[300];
    snprintf(tmp_path, sizeof tmp_path, "%s.tmp", g_db_path);

    FILE *fout = fopen(tmp_path, "w");
    if(!fout){ fclose(fin); return -1; }

    char line[AUTH_MAX_USER + AUTH_MAX_PASS + 8];
    int found = 0;

    while(fgets(line, sizeof line, fin)){
        char raw[sizeof line];
        strncpy(raw, line, sizeof raw-1); raw[sizeof raw-1]='\0';
        trim_nl(raw);
        char *colon = strchr(raw, ':');
        if(!colon){ continue; }
        *colon = '\0';
        const char *u = raw;
        const char *p = colon + 1;

        if(strcmp(u, target_user)==0){
            found = 1;
            if(new_user == NULL && new_pass == NULL){
                /* delete */
            }else{
              const char *write_user = new_user ? (const char *)new_user : u;
              const char *write_pass = new_pass ? (const char *)new_pass : p;
              fprintf(fout, "%s:%s\n", write_user, write_pass);
            }
            if(did_change) *did_change = 1;
        }else{
            fprintf(fout, "%s:%s\n", u, p);
        }
    }

    fclose(fin);
    fclose(fout);

    if(!found){
        remove(tmp_path);
        errno = ENOENT;
        return -1;
    }

    remove(g_db_path);
    if(rename(tmp_path, g_db_path) != 0){
        FILE *src = fopen(tmp_path, "r");
        FILE *dst = fopen(g_db_path, "w");
        if(!src || !dst){ if(src) fclose(src); if(dst) fclose(dst); remove(tmp_path); return -1; }
        char buf[4096]; size_t n;
        while((n=fread(buf,1,sizeof buf,src))>0) fwrite(buf,1,n,dst);
        fclose(src); fclose(dst); remove(tmp_path);
    }
    return 0;
}

int32_t auth_delete(const int8_t *username){
    if(!username || !*username) return -1;
    int changed = 0;
    return rewrite_db_skip_or_replace(username, NULL, NULL, &changed);
}

int32_t auth_change_password(const int8_t *username, const int8_t *new_password){
    if(!username || !new_password || !*new_password) return -1;
    int changed = 0;
    return rewrite_db_skip_or_replace(username, NULL, new_password, &changed);
}

int32_t auth_rename_user(const int8_t *old_username, const int8_t *new_username){
    if(!old_username || !new_username || !*new_username) return -1;

    FILE *f = fopen(g_db_path, "r");
    if(!f) return -1;
    if(find_user(f, new_username, NULL, 0)){
        fclose(f);
        errno = EEXIST;
        return -1;
    }
    fclose(f);

    int changed = 0;
    return rewrite_db_skip_or_replace(old_username, new_username, NULL, &changed);
}
