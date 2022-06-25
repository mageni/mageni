# OpenVAS Vulnerability Test
# $Id: deb_2217_1.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2217-1 (dhcp3)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.69561");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-0997");
  script_name("Debian Security Advisory DSA 2217-1 (dhcp3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202217-1");
  script_tag(name:"insight", value:"Sebastian Krahmer and Marius Tomaschewski discovered that dhclient of
dhcp3, a DHCP client, is not properly filtering shell meta-characters
in certain options in DHCP server responses.  These options are reused in
an insecure fashion by dhclient scripts.  This allows an attacker to execute
arbitrary commands with the privileges of such a process by sending crafted
DHCP options to a client using a rogue server.


For the oldstable distribution (lenny), this problem has been fixed in
version 3.1.1-6+lenny5.

For the stable (squeeze), testing (wheezy) and unstable (sid) distributions,
this problem has been fixed in an additional update for isc-dhcp.");

  script_tag(name:"solution", value:"We recommend that you upgrade your dhcp3 packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to dhcp3
announced via advisory DSA 2217-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"dhcp-client", ver:"3.1.1-6+lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dhcp3-client", ver:"3.1.1-6+lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dhcp3-client-udeb", ver:"3.1.1-6+lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dhcp3-common", ver:"3.1.1-6+lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dhcp3-dev", ver:"3.1.1-6+lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dhcp3-relay", ver:"3.1.1-6+lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dhcp3-server", ver:"3.1.1-6+lenny5", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dhcp3-server-ldap", ver:"3.1.1-6+lenny5", rls:"DEB5")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}