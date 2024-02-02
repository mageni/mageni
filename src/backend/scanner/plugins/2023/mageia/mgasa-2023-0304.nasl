# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0304");
  script_cve_id("CVE-2023-31122", "CVE-2023-43622", "CVE-2023-45802");
  script_tag(name:"creation_date", value:"2023-10-30 04:12:08 +0000 (Mon, 30 Oct 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-01 18:11:02 +0000 (Wed, 01 Nov 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0304)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(8|9)");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0304");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0304.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32415");
  script_xref(name:"URL", value:"https://downloads.apache.org/httpd/CHANGES_2.4.58");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache' package(s) announced via the MGASA-2023-0304 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Apache has been updated to version 2.4.58 to fix several security
issues.

CVE-2023-45802: Apache HTTP Server: HTTP/2 stream memory not reclaimed
right away on RST (cve.mitre.org)
When a HTTP/2 stream was reset (RST frame) by a client, there was a time
window were the request's memory resources were not reclaimed
immediately. Instead, de-allocation was deferred to connection close.
A client could send new requests and resets, keeping the connection busy
and open and causing the memory footprint to keep on growing. On
connection close, all resources were reclaimed, but the process might
run out of memory before that.
This was found by the reporter during testing of CVE-2023-44487
(HTTP/2 Rapid Reset Exploit) with their own test client. During 'normal'
HTTP/2 use, the probability to hit this bug is very low. The kept memory
would not become noticeable before the connection closes or times out.
Users are recommended to upgrade to version 2.4.58, which fixes the
issue.
Credits: Will Dormann of Vul Labs

CVE-2023-43622: Apache HTTP Server: DoS in HTTP/2 with initial windows
size 0 (cve.mitre.org)
An attacker, opening a HTTP/2 connection with an initial window size of
0, was able to block handling of that connection indefinitely in Apache
HTTP Server. This could be used to exhaust worker resources in the
server, similar to the well known 'slow loris' attack pattern.
This has been fixed in version 2.4.58, so that such connection are
terminated properly after the configured connection timeout.
This issue affects Apache HTTP Server: from 2.4.55 through 2.4.57.
Users are recommended to upgrade to version 2.4.58, which fixes the
issue.
Credits: Prof. Sven Dietrich (City University of New York)

CVE-2023-31122: mod_macro buffer over-read
(cve.mitre.org)
Out-of-bounds Read vulnerability in mod_macro of Apache HTTP Server. This issue affects Apache HTTP Server: through 2.4.57.
Credits: David Shoon (github/davidshoon)");

  script_tag(name:"affected", value:"'apache' package(s) on Mageia 8, Mageia 9.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"apache", rpm:"apache~2.4.58~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-devel", rpm:"apache-devel~2.4.58~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-doc", rpm:"apache-doc~2.4.58~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-htcacheclean", rpm:"apache-htcacheclean~2.4.58~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_brotli", rpm:"apache-mod_brotli~2.4.58~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_cache", rpm:"apache-mod_cache~2.4.58~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_dav", rpm:"apache-mod_dav~2.4.58~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_dbd", rpm:"apache-mod_dbd~2.4.58~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_http2", rpm:"apache-mod_http2~2.4.58~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_ldap", rpm:"apache-mod_ldap~2.4.58~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_proxy", rpm:"apache-mod_proxy~2.4.58~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_proxy_html", rpm:"apache-mod_proxy_html~2.4.58~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_session", rpm:"apache-mod_session~2.4.58~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_ssl", rpm:"apache-mod_ssl~2.4.58~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_suexec", rpm:"apache-mod_suexec~2.4.58~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_userdir", rpm:"apache-mod_userdir~2.4.58~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"apache", rpm:"apache~2.4.58~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-devel", rpm:"apache-devel~2.4.58~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-doc", rpm:"apache-doc~2.4.58~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-htcacheclean", rpm:"apache-htcacheclean~2.4.58~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_brotli", rpm:"apache-mod_brotli~2.4.58~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_cache", rpm:"apache-mod_cache~2.4.58~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_dav", rpm:"apache-mod_dav~2.4.58~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_dbd", rpm:"apache-mod_dbd~2.4.58~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_http2", rpm:"apache-mod_http2~2.4.58~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_ldap", rpm:"apache-mod_ldap~2.4.58~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_proxy", rpm:"apache-mod_proxy~2.4.58~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_proxy_html", rpm:"apache-mod_proxy_html~2.4.58~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_session", rpm:"apache-mod_session~2.4.58~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_ssl", rpm:"apache-mod_ssl~2.4.58~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_suexec", rpm:"apache-mod_suexec~2.4.58~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_userdir", rpm:"apache-mod_userdir~2.4.58~1.mga9", rls:"MAGEIA9"))) {
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
