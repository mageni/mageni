# OpenVAS Vulnerability Test
# $Id: deb_3024.nasl 14302 2019-03-19 08:28:48Z cfischer $
# Auto-generated from advisory DSA 3024-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703024");
  script_version("$Revision: 14302 $");
  script_cve_id("CVE-2014-5270");
  script_name("Debian Security Advisory DSA 3024-1 (gnupg - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-09-11 00:00:00 +0200 (Thu, 11 Sep 2014)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-3024.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"gnupg on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), this problem has been fixed in
version 1.4.12-7+deb7u6.

For the testing (jessie) and unstable distribution (sid), this
problem has been fixed in version 1.4.18-4.

We recommend that you upgrade your gnupg packages.");
  script_tag(name:"summary", value:"Genkin, Pipman and Tromer discovered a side-channel attack on Elgamal
encryption subkeys
(CVE-2014-5270).

In addition, this update hardens GnuPG's behaviour when treating
keyserver responses. GnuPG now filters keyserver responses to only
accepts those keyid's actually requested by the user.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"gnupg", ver:"1.4.12-7+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gnupg-curl", ver:"1.4.12-7+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gpgv", ver:"1.4.12-7+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"gpgv-win32", ver:"1.4.12-7+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}