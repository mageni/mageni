# OpenVAS Vulnerability Test
# $Id: deb_2896.nasl 14277 2019-03-18 14:45:38Z cfischer $
# Auto-generated from advisory DSA 2896-1 using nvtgen 1.0
# Script version: 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.702896");
  script_version("$Revision: 14277 $");
  script_cve_id("CVE-2014-0160");
  script_name("Debian Security Advisory DSA 2896-1 (openssl - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:45:38 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-04-07 00:00:00 +0200 (Mon, 07 Apr 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2896.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"openssl on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy),
this problem has been fixed in version 1.0.1e-2+deb7u5.

For the testing distribution (jessie), this problem has been fixed in
version 1.0.1g-1.

For the unstable distribution (sid), this problem has been fixed in
version 1.0.1g-1.

We recommend that you upgrade your openssl packages.");
  script_tag(name:"summary", value:"A vulnerability has been discovered
in OpenSSL's support for the TLS/DTLS Heartbeat extension. Up to 64KB of memory
from either client or server can be recovered by an attacker. This vulnerability
might allow an attacker to compromise the private key and other sensitive data in
memory.

All users are urged to upgrade their openssl packages (especially
libssl1.0.0) and restart applications as soon as possible.

According to the currently available information, private keys should be
considered as compromised and regenerated as soon as possible. More
details will be communicated at a later time.

The oldstable distribution (squeeze) is not affected by this
vulnerability.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libssl-dev", ver:"1.0.1e-2+deb7u5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl-doc", ver:"1.0.1e-2+deb7u5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1e-2+deb7u5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssl1.0.0-dbg", ver:"1.0.1e-2+deb7u5", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openssl", ver:"1.0.1e-2+deb7u5", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}