# OpenVAS Vulnerability Test
# $Id: deb_2038_3.nasl 14275 2019-03-18 14:39:45Z cfischer $
# Description: Auto-generated from advisory DSA 2038-3 (pidgin)
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
  script_oid("1.3.6.1.4.1.25623.1.0.68661");
  script_version("$Revision: 14275 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-0420", "CVE-2010-0423");
  script_name("Debian Security Advisory DSA 2038-3 (pidgin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202038-3");
  script_tag(name:"insight", value:"The packages for Pidgin released as DSA 2038-2 had a regression, as they
unintentionally disabled the Silc, Simple, and Yahoo instant messaging
protocols. This update restore that functionality. For reference the
original advisory text below.

Several remote vulnerabilities have been discovered in Pidgin, a multi
protocol instant messaging client. The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2010-0420

Crafted nicknames in the XMPP protocol can crash Pidgin remotely.

CVE-2010-0423

Remote contacts may send too many custom smilies, crashing Pidgin.

Since a few months, Microsoft's servers for MSN have changed the protocol,
making Pidgin non-functional for use with MSN. It is not feasible to port
these changes to the version of Pidgin in Debian Lenny. This update
formalises that situation by disabling the protocol in the client. Users
of the MSN protocol are advised to use the version of Pidgin in the
repositories of backports.org.

For the stable distribution (lenny), these problems have been fixed in
version 2.4.3-4lenny8.

For the unstable distribution (sid), these problems have been fixed in
version 2.6.6-1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your pidgin package.");
  script_tag(name:"summary", value:"The remote host is missing an update to pidgin
announced via advisory DSA 2038-3.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libpurple-dev", ver:"2.4.3-4lenny8", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpurple-bin", ver:"2.4.3-4lenny8", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pidgin-data", ver:"2.4.3-4lenny8", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"finch-dev", ver:"2.4.3-4lenny8", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pidgin-dev", ver:"2.4.3-4lenny8", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pidgin-dbg", ver:"2.4.3-4lenny8", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"finch", ver:"2.4.3-4lenny8", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"pidgin", ver:"2.4.3-4lenny8", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libpurple0", ver:"2.4.3-4lenny8", rls:"DEB5")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}