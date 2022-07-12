# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.891834");
  script_version("2019-06-26T02:00:15+0000");
  script_cve_id("CVE-2018-14647", "CVE-2019-10160", "CVE-2019-5010", "CVE-2019-9636", "CVE-2019-9740", "CVE-2019-9947", "CVE-2019-9948");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-06-26 02:00:15 +0000 (Wed, 26 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-26 02:00:15 +0000 (Wed, 26 Jun 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1834-1] python2.7 security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/06/msg00022.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1834-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/921039");
  script_xref(name:"URL", value:"https://bugs.debian.org/921040");
  script_xref(name:"URL", value:"https://bugs.debian.org/924073");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python2.7'
  package(s) announced via the DSA-1834-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in Python, an interactive
high-level object-oriented language, including

CVE-2018-14647

Python's elementtree C accelerator failed to initialise Expat's hash
salt during initialization. This could make it easy to conduct
denial of service attacks against Expat by constructing an XML
document that would cause pathological hash collisions in Expat's
internal data structures, consuming large amounts CPU and RAM.

CVE-2019-5010

NULL pointer dereference using a specially crafted X509 certificate.

CVE-2019-9636

Improper Handling of Unicode Encoding (with an incorrect netloc)
during NFKC normalization resulting in information disclosure
(credentials, cookies, etc. that are cached against a given
hostname). A specially crafted URL could be incorrectly parsed to
locate cookies or authentication data and send that information to
a different host than when parsed correctly.

CVE-2019-9740

An issue was discovered in urllib2 where CRLF injection is possible
if the attacker controls a url parameter, as demonstrated by the
first argument to urllib.request.urlopen with \r\n (specifically in
the query string after a ? character) followed by an HTTP header or
a Redis command.

CVE-2019-9947

An issue was discovered in urllib2 where CRLF injection is possible
if the attacker controls a url parameter, as demonstrated by the
first argument to urllib.request.urlopen with \r\n (specifically in
the path component of a URL that lacks a ? character) followed by an
HTTP header or a Redis command. This is similar to the CVE-2019-9740
query string issue.

CVE-2019-9948

urllib supports the local_file: scheme, which makes it easier for
remote attackers to bypass protection mechanisms that blacklist
file: URIs, as demonstrated by triggering a
urllib.urlopen('local_file:///etc/passwd') call.

CVE-2019-10160

A security regression of CVE-2019-9636 was discovered which still
allows an attacker to exploit CVE-2019-9636 by abusing the user and
password parts of a URL. When an application parses user-supplied
URLs to store cookies, authentication credentials, or other kind of
information, it is possible for an attacker to provide specially
crafted URLs to make the application locate host-related information
(e.g. cookies, authentication data) and send them to a different
host than where it should, unlike if the URLs had been correctly
parsed. The result of an attack may vary based on the application.");

  script_tag(name:"affected", value:"'python2.7' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
2.7.9-2+deb8u3.

We recommend that you upgrade your python2.7 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"idle-python2.7", ver:"2.7.9-2+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython2.7", ver:"2.7.9-2+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython2.7-dbg", ver:"2.7.9-2+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython2.7-dev", ver:"2.7.9-2+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython2.7-minimal", ver:"2.7.9-2+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython2.7-stdlib", ver:"2.7.9-2+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython2.7-testsuite", ver:"2.7.9-2+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.9-2+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python2.7-dbg", ver:"2.7.9-2+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python2.7-dev", ver:"2.7.9-2+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python2.7-doc", ver:"2.7.9-2+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python2.7-examples", ver:"2.7.9-2+deb8u3", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python2.7-minimal", ver:"2.7.9-2+deb8u3", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);