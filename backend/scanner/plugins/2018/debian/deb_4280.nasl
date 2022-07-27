###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4280.nasl 14270 2019-03-18 14:24:29Z cfischer $
#
# Auto-generated from advisory DSA 4280-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.704280");
  script_version("$Revision: 14270 $");
  script_cve_id("CVE-2018-15473");
  script_name("Debian Security Advisory DSA 4280-1 (openssh - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:24:29 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-08-22 00:00:00 +0200 (Wed, 22 Aug 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4280.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"openssh on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), this problem has been fixed in
version 1:7.4p1-10+deb9u4.

We recommend that you upgrade your openssh packages.

For the detailed security status of openssh please refer to
its security tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openssh");
  script_tag(name:"summary", value:"Dariusz Tytko, Michal Sajdak and Qualys Security discovered that
OpenSSH, an implementation of the SSH protocol suite, was prone to a
user enumeration vulnerability. This would allow a remote attacker to
check whether a specific user account existed on the target server.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"openssh-client", ver:"1:7.4p1-10+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openssh-client-ssh1", ver:"1:7.4p1-10+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openssh-server", ver:"1:7.4p1-10+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openssh-sftp-server", ver:"1:7.4p1-10+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ssh", ver:"1:7.4p1-10+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ssh-askpass-gnome", ver:"1:7.4p1-10+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ssh-krb5", ver:"1:7.4p1-10+deb9u4", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}