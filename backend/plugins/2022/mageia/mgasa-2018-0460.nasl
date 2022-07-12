# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0460");
  script_cve_id("CVE-2017-15710", "CVE-2017-15715", "CVE-2018-11763", "CVE-2018-1283", "CVE-2018-1301", "CVE-2018-1302", "CVE-2018-1303", "CVE-2018-1312", "CVE-2018-1333");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2018-0460)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0460");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0460.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22833");
  script_xref(name:"URL", value:"http://www.apache.org/dist/httpd/CHANGES_2.4");
  script_xref(name:"URL", value:"http://www.apache.org/dist/httpd/CHANGES_2.4.37");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-05/msg00023.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-08/msg00123.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-10/msg00081.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache' package(s) announced via the MGASA-2018-0460 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"mod_authnz_ldap, if configured with AuthLDAPCharsetConfig, uses the
Accept-Language header value to lookup the right charset encoding when
verifying the user's credentials. If the header value is not present in
the charset conversion table, a fallback mechanism is used to truncate
it to a two characters value to allow a quick retry (for example,
'en-US' is truncated to 'en'). A header value of less than two
characters forces an out of bound write of one NUL byte to a memory
location that is not part of the string. In the worst case, quite
unlikely, the process would crash which could be used as a Denial of
Service attack. In the more likely case, this memory is already
reserved for future use and the issue has no effect at all
(CVE-2017-15710).

A regular expression could match '$' to a newline character in a
malicious filename, rather than matching only the end of the filename.
leading to corruption of uploaded files (CVE-2017-15715).

When mod_session is configured to forward its session data to CGI
applications (SessionEnv on, not the default), a remote user may
influence their content by using a \'Session\' header leading to
unexpected behavior (CVE-2018-1283).

Due to an out of bound access after a size limit being reached by
reading the HTTP header, a specially crafted request could lead to
remote denial of service (CVE-2018-1301).

When an HTTP/2 stream was destroyed after being handled, it could have
written a NULL pointer potentially to an already freed memory. The
memory pools maintained by the server make this vulnerability hard to
trigger in usual configurations, the reporter and the team could not
reproduce it outside debug builds, so it is classified as low risk
(CVE-2018-1302).

A specially crafted HTTP request header could lead to crash due to an
out of bound read while preparing data to be cached in shared memory
(CVE-2018-1303).

When generating an HTTP Digest authentication challenge, the nonce sent
to prevent reply attacks was not correctly generated using a pseudo-
random seed. In a cluster of servers using a common Digest
authentication configuration, HTTP requests could be replayed across
servers by an attacker without detection (CVE-2018-1312).

Fixed a worker exhaustion that could have lead to a denial of service
via specially crafted HTTP/2 requests (CVE-2018-1333).

In Apache HTTP Server by sending continuous, large SETTINGS frames a
client can occupy a connection, server thread and CPU time without any
connection timeout coming to effect. This affects only HTTP/2
connections (CVE-2018-11763).

The apache package has been updated to version 2.4.37, fixing these
issues and several other bugs. See the upstream CHANGES files for
details.");

  script_tag(name:"affected", value:"'apache' package(s) on Mageia 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"apache", rpm:"apache~2.4.37~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-devel", rpm:"apache-devel~2.4.37~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-doc", rpm:"apache-doc~2.4.37~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-htcacheclean", rpm:"apache-htcacheclean~2.4.37~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_cache", rpm:"apache-mod_cache~2.4.37~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_dav", rpm:"apache-mod_dav~2.4.37~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_dbd", rpm:"apache-mod_dbd~2.4.37~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_http2", rpm:"apache-mod_http2~2.4.37~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_ldap", rpm:"apache-mod_ldap~2.4.37~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_proxy", rpm:"apache-mod_proxy~2.4.37~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_proxy_html", rpm:"apache-mod_proxy_html~2.4.37~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_session", rpm:"apache-mod_session~2.4.37~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_ssl", rpm:"apache-mod_ssl~2.4.37~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_suexec", rpm:"apache-mod_suexec~2.4.37~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_userdir", rpm:"apache-mod_userdir~2.4.37~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
