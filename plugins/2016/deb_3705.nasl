# OpenVAS Vulnerability Test
# $Id: deb_3705.nasl 14279 2019-03-18 14:48:34Z cfischer $
# Auto-generated from advisory DSA 3705-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703705");
  script_version("$Revision: 14279 $");
  script_cve_id("CVE-2016-8615", "CVE-2016-8616", "CVE-2016-8617", "CVE-2016-8618", "CVE-2016-8619", "CVE-2016-8620", "CVE-2016-8621", "CVE-2016-8622", "CVE-2016-8623", "CVE-2016-8624");
  script_name("Debian Security Advisory DSA 3705-1 (curl - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-11-03 00:00:00 +0100 (Thu, 03 Nov 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3705.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"curl on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie), these problems have been fixed in
version 7.38.0-4+deb8u5.

For the unstable distribution (sid), these problems have been fixed in
version 7.51.0-1.

We recommend that you upgrade your curl packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered in cURL, an URL transfer library:

CVE-2016-8615
It was discovered that a malicious HTTP server could inject new
cookies for arbitrary domains into a cookie jar.

CVE-2016-8616
It was discovered that when re-using a connection, curl was doing case
insensitive comparisons of user name and password with the existing
connections.

CVE-2016-8617
It was discovered that on systems with 32-bit addresses in userspace
(e.g. x86, ARM, x32), the output buffer size value calculated in the
base64 encode function would wrap around if input size was at least
1GB of data, causing an undersized output buffer to be allocated.

CVE-2016-8618
It was discovered that the curl_maprintf() function could be tricked
into doing a double-free due to an unsafe size_t multiplication on
systems using 32 bit size_t variables.

CVE-2016-8619
It was discovered that the Kerberos implementation could be
tricked into doing a double-free when reading one of the length fields
from a socket.

CVE-2016-8620It was discovered that the curl tool's globbing
feature could write
to invalid memory areas when parsing invalid ranges.

CVE-2016-8621
It was discovered that the function curl_getdate could read out of
bounds when parsing invalid date strings.

CVE-2016-8622
It was discovered that the URL percent-encoding decode function would
return a signed 32bit integer variable as length, even though it
allocated a destination buffer larger than 2GB, which would lead to
a out-of-bounds write.

CVE-2016-8623
It was discovered that libcurl could access an already-freed memory
area due to concurrent access to shared cookies. This could lead to
a denial of service or disclosure of sensitive information.

CVE-2016-8624
It was discovered that curl wouldn't parse the authority component of
a URL correctly when the host name part ends with a '#' character,
and could be tricked into connecting to a different host.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"curl", ver:"7.38.0-4+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3", ver:"7.38.0-4+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3-dbg", ver:"7.38.0-4+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.38.0-4+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl3-nss", ver:"7.38.0-4+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl4-doc", ver:"7.38.0-4+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl4-gnutls-dev", ver:"7.38.0-4+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl4-nss-dev", ver:"7.38.0-4+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcurl4-openssl-dev", ver:"7.38.0-4+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}