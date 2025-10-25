
#include "proto.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

// ---------------- Baseline: TLS ECHO ----------------

// Build a simple message for the echo baseline.
// TODO: (Optional) change the payload content (e.g., include your name or a counter).
int proto_build_client_message(char* out, size_t outsz) {
    return snprintf(out, outsz, "HELLO FROM ALEX AND ERIK");
}

// Server handler for baseline: just echo back the same line.
// TODO: Replace this logic with PT->ET conversion per assignment spec.
int proto_handle_server_request(const char* in_line, char* out_line, size_t outsz) {
    struct tm tm_in = {0};
    char tz[3] = {0};

    if (sscanf(in_line, "%d-%d-%d %d:%d:%d %2s",
                &tm_in.tm_year, &tm_in.tm_mon, &tm_in.tm_mday,
                &tm_in.tm_hour, &tm_in.tm_min, &tm_in.tm_sec, tz) != 7) {
        return snprintf(out_line, outsz, "ERR invalid input");
    }

    tm_in.tm_year -= 1900;
    tm_in.tm_mon -= 1;

    time_t t = timegm(&tm_in);
    if(strcmp(tz,"PT") == 0) t += 8 * 3600;
    else if(strcmp(tz,"ET") == 0) t += 5 * 3600;
    else return snprintf(out_line,outsz,"ERR unknown TZ");

    t -= 5 * 3600;
    struct tm * tm_et = gmtime(&t);
      
    return snprintf(out_line,outsz, "%04d-%02d-%02d %02d:%02d:%02d ET",
                    tm_et->tm_year + 1900, tm_et->tm_mon + 1, tm_et->tm_mday,
                    tm_et->tm_hour, tm_et->tm_min, tm_et->tm_sec);
}

// Guidance for time-converter functions is in proto.h (see TODOs).
