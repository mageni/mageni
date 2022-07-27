###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4322.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DSA 4322-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704322");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2018-10933");
  script_name("Debian Security Advisory DSA 4322-1 (libssh - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-10-17 00:00:00 +0200 (Wed, 17 Oct 2018)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4322.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"libssh on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), this problem has been fixed in
version 0.7.3-2+deb9u1.

We recommend that you upgrade your libssh packages.

For the detailed security status of libssh please refer to its
security tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libssh");
  script_tag(name:"summary", value:"Peter Winter-Smith of NCC Group discovered that libssh, a tiny C SSH
library, contains an authentication bypass vulnerability in the server
code. An attacker can take advantage of this flaw to successfully
authenticate without any credentials by presenting the server an
SSH2_MSG_USERAUTH_SUCCESS message in place of the
SSH2_MSG_USERAUTH_REQUEST message which the server would expect to
initiate authentication.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libssh-4", ver:"0.7.3-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssh-dev", ver:"0.7.3-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssh-doc", ver:"0.7.3-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssh-gcrypt-4", ver:"0.7.3-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libssh-gcrypt-dev", ver:"0.7.3-2+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}