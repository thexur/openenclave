// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <unistd.h>
#include "tlscli.h"

int main()
{
    int retval;
    tlscli_t* cli = NULL;
    tls_error_t error;
    const char CRT_PATH[] = "/tmp/oe_attested_cert.der";
    const char PK_PATH[] = "/tmp/oe_private_key.pem";

    if ((retval = tlscli_startup(&error)) != 0)
    {
        tls_dump_error(&error);
        exit(1);
    }

    if ((retval = tlscli_connect(
             true, "127.0.0.1", "12345", CRT_PATH, PK_PATH, &cli, &error)) != 0)
    {
        tls_dump_error(&error);
        exit(1);
    }

    const char message[] = "abcdefghijklmnopqrstuvwxyz";

    for (size_t i = 0; i < 10; i++)
    {
        printf("CLIENT.WRITE\n");

        retval = tlscli_write(cli, message, sizeof(message), &error);
        if (retval < 0)
        {
            tls_dump_error(&error);
            exit(1);
        }

        printf("cli.wrote=%d\n", retval);

        char buf[1024];

        printf("CLIENT.READ\n");

        retval = tlscli_read(cli, buf, sizeof(buf), &error);
        if (retval < 0)
        {
            tls_dump_error(&error);
            exit(1);
        }
    }

    tlscli_disconnect(cli, &error);

    printf("CLIENT.DONE\n");
    return 0;
}
