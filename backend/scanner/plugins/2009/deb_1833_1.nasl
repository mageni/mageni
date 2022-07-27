# OpenVAS Vulnerability Test
# $Id: deb_1833_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1833-1 (dhcp3)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Several remote vulnerabilities have been discovered in ISC's DHCP
implementation:

It was discovered that dhclient does not properly handle overlong
subnet mask options, leading to a stack-based buffer overflow and
possible arbitrary code execution.  (CVE-2009-0692)

Christoph Biedl discovered that the DHCP server may terminate when
receiving certain well-formed DHCP requests, provided that the server
configuration mixes host definitions using dhcp-client-identifier
and hardware ethernet.  This vulnerability only affects the lenny
versions of dhcp3-server and dhcp3-server-ldap.  (CVE-2009-1892)

For the old stable distribution (etch), these problems have been fixed
in version 3.0.4-13+etch2.

For the stable distribution (lenny), this problem has been fixed in
version 3.1.1-6+lenny2.

For the unstable distribution (sid), these problems will be fixed
soon.

We recommend that you upgrade your dhcp3 packages.";
tag_summary = "The remote host is missing an update to dhcp3
announced via advisory DSA 1833-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201833-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.307614");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
 script_cve_id("CVE-2009-0692", "CVE-2009-1892");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1833-1 (dhcp3)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"dhcp3-dev", ver:"3.0.4-13+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-relay", ver:"3.0.4-13+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-client", ver:"3.0.4-13+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-common", ver:"3.0.4-13+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-server", ver:"3.0.4-13+etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp-client", ver:"3.1.1-6+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-server", ver:"3.1.1-6+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-dev", ver:"3.1.1-6+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-server-ldap", ver:"3.1.1-6+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-relay", ver:"3.1.1-6+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-client", ver:"3.1.1-6+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-common", ver:"3.1.1-6+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
