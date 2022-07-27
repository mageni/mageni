###############################################################################
# OpenVAS Vulnerability Test
#
# Auto-generated from advisory DSA 3963-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703963");
  script_version("2019-05-14T07:15:16+0000");
  script_cve_id("CVE-2017-1000115", "CVE-2017-1000116", "CVE-2017-9462");
  script_name("Debian Security Advisory DSA 3963-1 (mercurial - security update)");
  script_tag(name:"last_modification", value:"2019-05-14 07:15:16 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2017-09-04 00:00:00 +0200 (Mon, 04 Sep 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2017/dsa-3963.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(9|8)");
  script_tag(name:"affected", value:"mercurial on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), these problems have been fixed
in version 3.1.2-2+deb8u4.

For the stable distribution (stretch), these problems have been fixed in
version 4.0-1+deb9u1.

We recommend that you upgrade your mercurial packages.");
  script_tag(name:"summary", value:"Several issues were discovered in Mercurial, a distributed revision
control system.

CVE-2017-9462 (fixed in stretch only)

Jonathan Claudius of Mozilla discovered that repositories served
over stdio could be tricked into granting authorized users access to
the Python debugger.

CVE-2017-1000115
Mercurial's symlink auditing was incomplete, and could be abused to
write files outside the repository.

CVE-2017-1000116
Joern Schneeweisz discovered that Mercurial did not correctly handle
maliciously constructed ssh:// URLs. This allowed an attacker to run
an arbitrary shell command.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"mercurial", ver:"4.0-1+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mercurial-common", ver:"4.0-1+deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mercurial", ver:"3.1.2-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mercurial-common", ver:"3.1.2-2+deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}