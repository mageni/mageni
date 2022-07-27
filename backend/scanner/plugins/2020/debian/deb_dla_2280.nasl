# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892280");
  script_version("2020-07-17T12:33:55+0000");
  script_cve_id("CVE-2018-20406", "CVE-2018-20852", "CVE-2019-10160", "CVE-2019-11340", "CVE-2019-16056", "CVE-2019-16935", "CVE-2019-18348", "CVE-2019-5010", "CVE-2019-9636", "CVE-2019-9740", "CVE-2019-9947", "CVE-2019-9948", "CVE-2020-14422", "CVE-2020-8492");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-07-20 10:03:49 +0000 (Mon, 20 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-17 12:33:55 +0000 (Fri, 17 Jul 2020)");
  script_name("Debian LTS: Security Advisory for python3.5 (DLA-2280-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/07/msg00011.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2280-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/924072");
  script_xref(name:"URL", value:"https://bugs.debian.org/921064");
  script_xref(name:"URL", value:"https://bugs.debian.org/940901");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.5'
  package(s) announced via the DLA-2280-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Python, an interactive
high-level object-oriented language.

CVE-2018-20406

Modules/_pickle.c has an integer overflow via a large LONG_BINPUT
value that is mishandled during a 'resize to twice the size'
attempt. This issue might cause memory exhaustion, but is only
relevant if the pickle format is used for serializing tens or
hundreds of gigabytes of data.

CVE-2018-20852

http.cookiejar.DefaultPolicy.domain_return_ok in
Lib/http/cookiejar.py does not correctly validate the domain: it
can be tricked into sending existing cookies to the wrong
server. An attacker may abuse this flaw by using a server with a
hostname that has another valid hostname as a suffix (e.g.,
pythonicexample.com to steal cookies for example.com). When a
program uses http.cookiejar.DefaultPolicy and tries to do an HTTP
connection to an attacker-controlled server, existing cookies can
be leaked to the attacker.

CVE-2019-5010

An exploitable denial-of-service vulnerability exists in the X509
certificate parser. A specially crafted X509 certificate can cause
a NULL pointer dereference, resulting in a denial of service. An
attacker can initiate or accept TLS connections using crafted
certificates to trigger this vulnerability.

CVE-2019-9636

Improper Handling of Unicode Encoding (with an incorrect netloc)
during NFKC normalization. The impact is: Information disclosure
(credentials, cookies, etc. that are cached against a given
hostname). The components are: urllib.parse.urlsplit,
urllib.parse.urlparse. The attack vector is: A specially crafted
URL could be incorrectly parsed to locate cookies or
authentication data and send that information to a different host
than when parsed correctly.

CVE-2019-9740

An issue was discovered in urllib2. CRLF injection is possible if
the attacker controls a url parameter, as demonstrated by the
first argument to urllib.request.urlopen with \r\n (specifically
in the query string after a ? character) followed by an HTTP
header or a Redis command.

CVE-2019-9947

An issue was discovered in urllib2. CRLF injection is possible if
the attacker controls a url parameter, as demonstrated by the
first argument to urllib.request.urlopen with \r\n (specifically
in the path component of a URL that lacks a ? character) followed
by an HTTP header or a Redis command. This is similar to the
CVE-2019-9740 quer ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'python3.5' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
3.5.3-1+deb9u2.

We recommend that you upgrade your python3.5 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"idle-python3.5", ver:"3.5.3-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython3.5", ver:"3.5.3-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython3.5-dbg", ver:"3.5.3-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython3.5-dev", ver:"3.5.3-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython3.5-minimal", ver:"3.5.3-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython3.5-stdlib", ver:"3.5.3-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython3.5-testsuite", ver:"3.5.3-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3.5", ver:"3.5.3-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3.5-dbg", ver:"3.5.3-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3.5-dev", ver:"3.5.3-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3.5-doc", ver:"3.5.3-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3.5-examples", ver:"3.5.3-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3.5-minimal", ver:"3.5.3-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3.5-venv", ver:"3.5.3-1+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
