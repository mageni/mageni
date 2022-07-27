# OpenVAS Vulnerability Test
# $Id: deb_2038_2.nasl 8440 2018-01-17 07:58:46Z teissa $
# Description: Auto-generated from advisory DSA 2038-2 (pidgin)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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

include("revisions-lib.inc");
tag_insight = "The packages for Pidgin released as DSA 2038-1 had a regression, as they
unintentionally disabled the Zephyr instant messaging protocol. This
update restores Zephyr functionality. For reference the original
advisory text below.

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
repositories of www.backports.org.

For the stable distribution (lenny), these problems have been fixed in
version 2.4.3-4lenny7.

For the unstable distribution (sid), these problems have been fixed in
version 2.6.6-1.

We recommend that you upgrade your pidgin package.";
tag_summary = "The remote host is missing an update to pidgin
announced via advisory DSA 2038-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202038-2";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.313387");
 script_version("$Revision: 8440 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-06-03 22:55:24 +0200 (Thu, 03 Jun 2010)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2010-0420", "CVE-2010-0423");
 script_name("Debian Security Advisory DSA 2038-2 (pidgin)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"pidgin-data", ver:"2.4.3-4lenny7", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pidgin-dev", ver:"2.4.3-4lenny7", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"finch-dev", ver:"2.4.3-4lenny7", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpurple-bin", ver:"2.4.3-4lenny7", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpurple-dev", ver:"2.4.3-4lenny7", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpurple0", ver:"2.4.3-4lenny7", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"finch", ver:"2.4.3-4lenny7", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pidgin", ver:"2.4.3-4lenny7", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pidgin-dbg", ver:"2.4.3-4lenny7", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
