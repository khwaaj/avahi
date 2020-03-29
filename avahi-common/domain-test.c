/***
  This file is part of avahi.

  avahi is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.

  avahi is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
  or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
  Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with avahi; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
  USA.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "domain.h"
#include "malloc.h"

static int test_kt(const char* k, int ex) {
    int t = avahi_assess_domain_name(k);
    if (getenv("DEBUG")) {
        printf("%-48s -> %-4s [ ", k, (t == ex) ? "OK" : "FAIL");
        if (t != AVAHI_KEY_INVALID) {
            printf("%s ", (t & AVAHI_KEY_SERVICE_NAME) ? "SN" : "  ");
            printf("%s ", (t & AVAHI_KEY_SERVICE_SUBTYPE) ? "SST" : "   ");
            printf("%s ", (t & AVAHI_KEY_SERVICE_TYPE) ? "ST" : "  ");
            printf("%s ", (t & AVAHI_KEY_DOMAIN_NAME) ? "DN" : "  ");
            printf("%s ", (t & AVAHI_KEY_DOMAIN_ROOT) ? "DR" : "  ");
        } else {
            printf("%-15s ", t ? "---------------" : "");
        }
        printf("]\n");
    }
    return (t == ex);
}

int main(AVAHI_GCC_UNUSED int argc, AVAHI_GCC_UNUSED char *argv[]) {
    char *s;
    char t[256], r[256];
    const char *p;
    size_t size;
    char name[64], type[AVAHI_DOMAIN_NAME_MAX], domain[AVAHI_DOMAIN_NAME_MAX];

    printf("%s\n", s = avahi_normalize_name_strdup("foo.foo\\046."));
    avahi_free(s);

    printf("%s\n", s = avahi_normalize_name_strdup("foo.foo\\.foo."));
    avahi_free(s);


    printf("%s\n", s = avahi_normalize_name_strdup("fo\\\\o\\..f oo."));
    avahi_free(s);

    printf("%i\n", avahi_domain_equal("\\065aa bbb\\.\\046cc.cc\\\\.dee.fff.", "Aaa BBB\\.\\.cc.cc\\\\.dee.fff"));
    printf("%i\n", avahi_domain_equal("A", "a"));

    printf("%i\n", avahi_domain_equal("a", "aaa"));

    printf("%u = %u\n", avahi_domain_hash("ccc\\065aa.aa\\.b\\\\."), avahi_domain_hash("cccAaa.aa\\.b\\\\"));


    avahi_service_name_join(t, sizeof(t), "foo.foo.foo \\.", "_http._tcp", "test.local");
    printf("<%s>\n", t);

    avahi_service_name_split(t, name, sizeof(name), type, sizeof(type), domain, sizeof(domain));
    printf("name: <%s>; type: <%s>; domain <%s>\n", name, type, domain);

    avahi_service_name_join(t, sizeof(t), NULL, "_http._tcp", "one.two\\. .local");
    printf("<%s>\n", t);

    avahi_service_name_split(t, NULL, 0, type, sizeof(type), domain, sizeof(domain));
    printf("name: <>; type: <%s>; domain <%s>\n", type, domain);


    p = "--:---\\\\\\123\\065_äöü\\064\\.\\\\sjöödfhh.sdfjhskjdf";
    printf("unescaped: <%s>, rest: %s\n", avahi_unescape_label(&p, t, sizeof(t)), p);

    size = sizeof(r);
    s = r;

    printf("escaped: <%s>\n", avahi_escape_label(t, strlen(t), &s, &size));

    p = r;
    printf("unescaped: <%s>\n", avahi_unescape_label(&p, t, sizeof(t)));

    assert(avahi_is_valid_service_type_generic("_foo._bar._waldo"));
    assert(!avahi_is_valid_service_type_strict("_foo._bar._waldo"));
    assert(!avahi_is_valid_service_subtype("_foo._bar._waldo"));

    assert(avahi_is_valid_service_type_generic("_foo._tcp"));
    assert(avahi_is_valid_service_type_strict("_foo._tcp"));
    assert(!avahi_is_valid_service_subtype("_foo._tcp"));

    assert(!avahi_is_valid_service_type_generic("_foo._bar.waldo"));
    assert(!avahi_is_valid_service_type_strict("_foo._bar.waldo"));
    assert(!avahi_is_valid_service_subtype("_foo._bar.waldo"));

    assert(!avahi_is_valid_service_type_generic(""));
    assert(!avahi_is_valid_service_type_strict(""));
    assert(!avahi_is_valid_service_subtype(""));

    assert(avahi_is_valid_service_type_generic("_foo._sub._bar._tcp"));
    assert(!avahi_is_valid_service_type_strict("_foo._sub._bar._tcp"));
    assert(avahi_is_valid_service_subtype("_foo._sub._bar._tcp"));

    printf("%s\n", avahi_get_type_from_subtype("_foo._sub._bar._tcp"));

    assert(!avahi_is_valid_host_name(""));
    assert(!avahi_is_valid_host_name("."));
    assert(!avahi_is_valid_host_name("sf.ooo."));
    assert(!avahi_is_valid_host_name("sfooo."));
    assert(avahi_is_valid_host_name("sfooo"));

    assert(!avahi_is_valid_domain_name(".."));
    assert(avahi_is_valid_domain_name("."));
    assert(avahi_is_valid_domain_name(""));
    assert(!avahi_is_valid_domain_name("com.."));
    assert(avahi_is_valid_domain_name("com."));
    assert(avahi_is_valid_domain_name("com"));

    assert(avahi_normalize_name(".", t, sizeof(t)));
    assert(avahi_normalize_name("", t, sizeof(t)));

    assert(!avahi_is_valid_fqdn("."));
    assert(!avahi_is_valid_fqdn(""));
    assert(!avahi_is_valid_fqdn("foo"));
    assert(avahi_is_valid_fqdn("foo.bar"));
    assert(avahi_is_valid_fqdn("foo.bar."));
    assert(avahi_is_valid_fqdn("gnurz.foo.bar."));
    assert(!avahi_is_valid_fqdn("192.168.50.1"));
    assert(!avahi_is_valid_fqdn("::1"));
    assert(!avahi_is_valid_fqdn(".192.168.50.1."));

    assert(test_kt(NULL, AVAHI_KEY_INVALID));
    assert(test_kt("", AVAHI_KEY_DOMAIN_ROOT));
    assert(test_kt(".", AVAHI_KEY_DOMAIN_ROOT));
    assert(test_kt("..", AVAHI_KEY_INVALID));

    assert(test_kt("domain", AVAHI_KEY_DOMAIN_NAME));
    assert(test_kt("domain.", AVAHI_KEY_DOMAIN_NAME | AVAHI_KEY_DOMAIN_ROOT));
    assert(test_kt("domain..", AVAHI_KEY_INVALID));
    assert(test_kt(".domain", AVAHI_KEY_DOMAIN_NAME));
    assert(test_kt(".domain.", AVAHI_KEY_DOMAIN_NAME | AVAHI_KEY_DOMAIN_ROOT));
    assert(test_kt(".domain..", AVAHI_KEY_INVALID));

    assert(test_kt("host.domain", AVAHI_KEY_DOMAIN_NAME));
    assert(test_kt("sub.host.domain", AVAHI_KEY_DOMAIN_NAME));
    assert(test_kt("sub.sub.host.domain", AVAHI_KEY_DOMAIN_NAME));

    /* _bar is an unknown service protocol & will be treated as a normal domain name */
    assert(test_kt("foo._bar", AVAHI_KEY_DOMAIN_NAME));
    assert(test_kt("_foo._bar", AVAHI_KEY_DOMAIN_NAME));
    assert(test_kt("_foo._bar.", AVAHI_KEY_DOMAIN_NAME | AVAHI_KEY_DOMAIN_ROOT));
    assert(test_kt("_foo._bar.domain", AVAHI_KEY_DOMAIN_NAME));
    assert(test_kt("_foo._bar.domain.", AVAHI_KEY_DOMAIN_NAME | AVAHI_KEY_DOMAIN_ROOT));
    assert(test_kt("name._foo._bar.domain", AVAHI_KEY_DOMAIN_NAME));
    assert(test_kt("_name._foo._bar.domain", AVAHI_KEY_DOMAIN_NAME));

    /* _tcp & _udp are known service protocols and are treated the same, just test one of them */
    assert(test_kt("foo._tcp", AVAHI_KEY_INVALID));
    assert(test_kt("_svc._tcp", AVAHI_KEY_SERVICE_TYPE));
    assert(test_kt("_svc._tcp.", AVAHI_KEY_SERVICE_TYPE | AVAHI_KEY_DOMAIN_ROOT));
    assert(test_kt("_svc._tcp.domain", AVAHI_KEY_SERVICE_TYPE | AVAHI_KEY_DOMAIN_NAME));
    assert(test_kt("_svc._tcp.domain.", AVAHI_KEY_SERVICE_TYPE | AVAHI_KEY_DOMAIN_NAME | AVAHI_KEY_DOMAIN_ROOT));
    assert(test_kt("name._svc._tcp.domain", AVAHI_KEY_SERVICE_NAME | AVAHI_KEY_SERVICE_TYPE | AVAHI_KEY_DOMAIN_NAME));
    assert(test_kt("_name._svc._tcp.domain", AVAHI_KEY_SERVICE_NAME | AVAHI_KEY_SERVICE_TYPE | AVAHI_KEY_DOMAIN_NAME));

    assert(test_kt("foo._sub._svc._tcp", AVAHI_KEY_INVALID));
    assert(test_kt("_inst._sub._svc._tcp", AVAHI_KEY_SERVICE_SUBTYPE | AVAHI_KEY_SERVICE_TYPE));
    assert(test_kt("_inst._sub._svc._tcp.", AVAHI_KEY_SERVICE_SUBTYPE | AVAHI_KEY_SERVICE_TYPE | AVAHI_KEY_DOMAIN_ROOT));
    assert(test_kt("_inst._sub._svc._tcp.domain", AVAHI_KEY_SERVICE_SUBTYPE | AVAHI_KEY_SERVICE_TYPE | AVAHI_KEY_DOMAIN_NAME));
    assert(test_kt("_inst._sub._svc._tcp.domain.", AVAHI_KEY_SERVICE_SUBTYPE | AVAHI_KEY_SERVICE_TYPE | AVAHI_KEY_DOMAIN_NAME | AVAHI_KEY_DOMAIN_ROOT));
    assert(test_kt("name._inst._sub._svc._tcp.domain", AVAHI_KEY_SERVICE_NAME | AVAHI_KEY_SERVICE_SUBTYPE | AVAHI_KEY_SERVICE_TYPE | AVAHI_KEY_DOMAIN_NAME));
    assert(test_kt("_name._inst._sub._svc._tcp.domain", AVAHI_KEY_SERVICE_NAME | AVAHI_KEY_SERVICE_SUBTYPE | AVAHI_KEY_SERVICE_TYPE | AVAHI_KEY_DOMAIN_NAME));

    return 0;
}
