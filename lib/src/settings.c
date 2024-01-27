#include "magicnet.h"
#include "database.h"

int magicnet_setting_set(const char *key, const char *value) {
    return magicnet_database_setting_set(key, value);
}   

int magicnet_setting_set_int(const char *key, int value) {
    char value_str[256];
    sprintf(value_str, "%d", value);
    return magicnet_database_setting_set(key, value_str);
}

int magicnet_setting_set_timestamp(const char *key, time_t value) {
    char value_str[256];
    sprintf(value_str, "%ld", value);
    return magicnet_database_setting_set(key, value_str);
}

int magicnet_setting_get_int(const char *key, int *value_out) {
    char value[256];
    int result = magicnet_database_setting_get(key, value);
    if (result <= 0) {
        return result;
    }
    *value_out = atoi(value);
    return 0;
}

int magicnet_setting_get_timestamp(const char *key, time_t *value_out) {
    char value[256];
    int result = magicnet_database_setting_get(key, value);
    if (result <= 0) {
        return result;
    }
    *value_out = atol(value);
    return 0;
}

int magicnet_setting_get(const char *key, char *value_out) {
    return magicnet_database_setting_get(key, value_out);
}

bool magicnet_setting_exists(const char *key) {
    char value[256];
    int result = magicnet_database_setting_get(key, value);
    if (result <= 0) {
        return false;
    }
    return true;
}
