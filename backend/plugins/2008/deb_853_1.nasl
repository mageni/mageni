# OpenVAS Vulnerability Test
# $Id: deb_853_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 853-1
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largerly excerpted from the referenced
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
tag_solution = "For the stable distribution (sarge) these problems have been fixed in
version 0.10.10-2sarge3.

For the unstable distribution (sid) these problems have been fixed in
version 0.10.12-2.

We recommend that you upgrade your ethereal packages.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20853-1";
tag_summary = "The remote host is missing an update to ethereal
announced via advisory DSA 853-1.

Several security problems have been discovered in ethereal, a commonly
used network traffic analyser.  The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2005-2360
Memory allocation errors in the LDAP dissector can cause a denial
of service.

CVE-2005-2361
Various errors in the AgentX, PER, DOCSIS, RADIUS, Telnet, IS-IS,
HTTP, DCERPC, DHCP and SCTP dissectors can cause a denial of
service.

CVE-2005-2363
Various errors in the SMPP, 802.3, H1 and DHCP dissectors can
cause a denial of service.

CVE-2005-2364
Null pointer dereferences in the WBXML and GIOP dissectors can
cause a denial of service.

CVE-2005-2365
A buffer overflow and null pointer dereferences in the SMB
dissector can cause a denial of service.

CVE-2005-2366
Wrong address calculation in the BER dissector can cause an
infinite loop or abortion.

CVE-2005-2367
Format string vulnerabilities in the several dissectors allow
remote attackers to write to arbitrary memory locations and thus
gain privileges.

For the old stable distribution (woody) these problems have been fixed in
version 0.9.4-1woody13.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302375");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:03:37 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2005-2360", "CVE-2005-2361", "CVE-2005-2363", "CVE-2005-2364", "CVE-2005-2365", "CVE-2005-2366", "CVE-2005-2367");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 853-1 (ethereal)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"ethereal", ver:"0.9.4-1woody13", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ethereal-common", ver:"0.9.4-1woody13", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ethereal-dev", ver:"0.9.4-1woody13", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tethereal", ver:"0.9.4-1woody13", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ethereal", ver:"0.10.10-2sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ethereal-common", ver:"0.10.10-2sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ethereal-dev", ver:"0.10.10-2sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tethereal", ver:"0.10.10-2sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
