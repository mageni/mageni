# OpenVAS Vulnerability Test
# $Id: deb_3694.nasl 14279 2019-03-18 14:48:34Z cfischer $
# Auto-generated from advisory DSA 3694-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703694");
  script_version("$Revision: 14279 $");
  script_cve_id("CVE-2016-8860");
  script_name("Debian Security Advisory DSA 3694-1 (tor - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-10-18 00:00:00 +0200 (Tue, 18 Oct 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3694.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"tor on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie), this problem has been fixed in
version 0.2.5.12-3.

For the unstable distribution (sid), this problem has been fixed in
version 0.2.8.9-1.

For the experimental distribution, this problem has been fixed in
version 0.2.9.4-alpha-1.

We recommend that you upgrade your tor packages.");
  script_tag(name:"summary", value:"It has been discovered that Tor treats the contents of some buffer
chunks as if they were a NUL-terminated string. This issue could
enable a remote attacker to crash a Tor client, hidden service, relay,
or authority.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"tor", ver:"0.2.5.12-3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tor-dbg", ver:"0.2.5.12-3", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tor-geoipdb", ver:"0.2.5.12-3", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}