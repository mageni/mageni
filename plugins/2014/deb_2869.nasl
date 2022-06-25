# OpenVAS Vulnerability Test
# $Id: deb_2869.nasl 14302 2019-03-19 08:28:48Z cfischer $
# Auto-generated from advisory DSA 2869-1 using nvtgen 1.0
# Script version: 1.1
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.702869");
  script_version("$Revision: 14302 $");
  script_cve_id("CVE-2014-0092");
  script_name("Debian Security Advisory DSA 2869-1 (gnutls26 - incorrect certificate verification)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-03-03 00:00:00 +0100 (Mon, 03 Mar 2014)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2869.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"gnutls26 on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (squeeze), this problem has been fixed in
version 2.8.6-1+squeeze3.

For the stable distribution (wheezy), this problem has been fixed in
version 2.12.20-8+deb7u1.

For the testing distribution (jessie), this problem has been fixed in
version 2.12.23-13.

For the unstable distribution (sid), this problem has been fixed in
version 2.12.23-13.

We recommend that you upgrade your gnutls26 packages.");
  script_tag(name:"summary", value:"Nikos Mavrogiannopoulos of Red Hat discovered an X.509 certificate
verification issue in GnuTLS, an SSL/TLS library. A certificate
validation could be reported successfully even in cases were an error
would prevent all verification steps to be performed.

An attacker doing a man-in-the-middle of a TLS connection could use this
vulnerability to present a carefully crafted certificate that would be
accepted by GnuTLS as valid even if not signed by one of the trusted
authorities.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"gnutls-bin", ver:"2.8.6-1+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gnutls-doc", ver:"2.8.6-1+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"guile-gnutls", ver:"2.8.6-1+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutls-dev", ver:"2.8.6-1+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutls26", ver:"2.8.6-1+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutls26-dbg", ver:"2.8.6-1+squeeze3", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gnutls-bin", ver:"2.12.20-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gnutls26-doc", ver:"2.12.20-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"guile-gnutls", ver:"2.12.20-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutls-dev", ver:"2.12.20-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutls-openssl27", ver:"2.12.20-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutls26", ver:"2.12.20-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutls26-dbg", ver:"2.12.20-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgnutlsxx27", ver:"2.12.20-8+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}