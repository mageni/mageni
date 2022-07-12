# OpenVAS Vulnerability Test
# $Id: deb_1663_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1663-1 (net-snmp)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
tag_insight = "Several vulnerabilities have been discovered in NET SNMP, a suite of
Simple Network Management Protocol applications. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-0960

Wes Hardaker reported that the SNMPv3 HMAC verification relies on
the client to specify the HMAC length, which allows spoofing of
authenticated SNMPv3 packets.

CVE-2008-2292

John Kortink reported a buffer overflow in the __snprint_value
function in snmp_get causing a denial of service and potentially
allowing the execution of arbitrary code via a large OCTETSTRING
in an attribute value pair (AVP).

CVE-2008-4309

It was reported that an integer overflow in the
netsnmp_create_subtree_cache function in agent/snmp_agent.c allows
remote attackers to cause a denial of service attack via a crafted
SNMP GETBULK request.

For the stable distribution (etch), these problems has been fixed in
version 5.2.3-7etch4.

For the testing distribution (lenny) and unstable distribution (sid)
these problems have been fixed in version 5.4.1~dfsg-11.

We recommend that you upgrade your net-snmp package.";
tag_summary = "The remote host is missing an update to net-snmp
announced via advisory DSA 1663-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201663-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301589");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-11-19 16:52:57 +0100 (Wed, 19 Nov 2008)");
 script_cve_id("CVE-2008-0960", "CVE-2008-2292", "CVE-2008-4309");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1663-1 (net-snmp)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"libsnmp-base", ver:"5.2.3-7etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tkmib", ver:"5.2.3-7etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsnmp9-dev", ver:"5.2.3-7etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"snmp", ver:"5.2.3-7etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsnmp9", ver:"5.2.3-7etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsnmp-perl", ver:"5.2.3-7etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"snmpd", ver:"5.2.3-7etch4", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
