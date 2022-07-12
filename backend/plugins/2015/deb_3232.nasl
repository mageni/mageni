# OpenVAS Vulnerability Test
# $Id: deb_3232.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3232-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703232");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2015-3143", "CVE-2015-3144", "CVE-2015-3145", "CVE-2015-3148");
  script_name("Debian Security Advisory DSA 3232-1 (curl - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-04-22 00:00:00 +0200 (Wed, 22 Apr 2015)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3232.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"curl on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy),
these problems have been fixed in version 7.26.0-1+wheezy13.

For the upcoming stable distribution (jessie), these problems have been
fixed in version 7.38.0-4+deb8u1.

For the unstable distribution (sid), these problems have been fixed in
version 7.42.0-1.

We recommend that you upgrade your curl packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were
discovered in cURL, an URL transfer library:

CVE-2015-3143
NTLM-authenticated connections could be wrongly reused for requests
without any credentials set, leading to HTTP requests being sent
over the connection authenticated as a different user. This is
similar to the issue fixed in DSA-2849-1.

CVE-2015-3144
When parsing URLs with a zero-length hostname,
libcurl would try to read from an invalid memory address. This could
allow remote attackers to cause a denial of service (crash). This
issue only affects the upcoming stable (jessie) and unstable (sid)
distributions.

CVE-2015-3145When parsing HTTP cookies, if the parsed cookie's path
element
consists of a single double-quote, libcurl would try to write to an
invalid heap memory address. This could allow remote attackers to
cause a denial of service (crash). This issue only affects the
upcoming stable (jessie) and unstable (sid) distributions.

CVE-2015-3148
When doing HTTP requests using the Negotiate authentication method
along with NTLM, the connection used would not be marked as
authenticated, making it possible to reuse it and send requests for
one user over the connection authenticated as a different user.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"curl", ver:"7.26.0-1+wheezy13", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3:amd64", ver:"7.26.0-1+wheezy13", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3:i386", ver:"7.26.0-1+wheezy13", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3-dbg:amd64", ver:"7.26.0-1+wheezy13", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3-dbg:i386", ver:"7.26.0-1+wheezy13", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3-gnutls:amd64", ver:"7.26.0-1+wheezy13", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3-gnutls:i386", ver:"7.26.0-1+wheezy13", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3-nss:amd64", ver:"7.26.0-1+wheezy13", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3-nss:i386", ver:"7.26.0-1+wheezy13", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl4-gnutls-dev", ver:"7.26.0-1+wheezy13", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl4-nss-dev", ver:"7.26.0-1+wheezy13", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl4-openssl-dev", ver:"7.26.0-1+wheezy13", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}