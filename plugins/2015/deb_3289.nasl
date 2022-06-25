# OpenVAS Vulnerability Test
# $Id: deb_3289.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3289-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703289");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2015-1038");
  script_name("Debian Security Advisory DSA 3289-1 (p7zip - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-06-15 00:00:00 +0200 (Mon, 15 Jun 2015)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3289.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"p7zip on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy),
this problem has been fixed in version 9.20.1~dfsg.1-4+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 9.20.1~dfsg.1-4.1+deb8u1.

For the unstable distribution (sid), this problem has been fixed in
version 9.20.1~dfsg.1-4.2.

We recommend that you upgrade your p7zip packages.");
  script_tag(name:"summary", value:"Alexander Cherepanov discovered that
p7zip is susceptible to a directory traversal vulnerability. While extracting an
archive, it will extract symlinks and then follow them if they are referenced in
further entries. This can be exploited by a rogue archive to write
files outside the current directory.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"p7zip", ver:"9.20.1~dfsg.1-4+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"p7zip-full", ver:"9.20.1~dfsg.1-4+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}