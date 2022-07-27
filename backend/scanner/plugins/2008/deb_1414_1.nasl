# OpenVAS Vulnerability Test
# $Id: deb_1414_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1414-1
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
tag_insight = "Several remote vulnerabilities have been discovered in the Wireshark
network traffic analyzer, which may lead to denial of service or the
execution of arbitrary code. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2007-6114

Stefan Esser discovered a buffer overflow in the SSL dissector.
Fabiodds discovered a buffer overflow in the iSeries trace
dissector.

CVE-2007-6117

A programming error was discovered in the HTTP dissector, which may
lead to denial of service.

CVE-2007-6118

The MEGACO dissector could be tricked into ressource exhaustion.

CVE-2007-6120

The Bluetooth SDP dissector could be tricked into an endless loop.

CVE-2007-6121

The RPC portmap dissector could be tricked into dereferencing
a NULL pointer.

For the stable distribution (etch), these problems have been fixed
in version 0.99.4-5.etch.1. Updates packages for sparc will be provided
later.

For the old stable distribution (sarge), these problems have been
fixed in version 0.10.10-2sarge10. (In Sarge Wireshark used to be
called Ethereal). Updates packages for sparc and m68k will be provided
later.

We recommend that you upgrade your wireshark/ethereal packages.";
tag_summary = "The remote host is missing an update to wireshark
announced via advisory DSA 1414-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201414-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300220");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:23:47 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2007-6114", "CVE-2007-6117", "CVE-2007-6118", "CVE-2007-6120", "CVE-2007-6121");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1414-1 (wireshark)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"ethereal-common", ver:"0.99.4-5.etch.1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ethereal", ver:"0.99.4-5.etch.1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ethereal-dev", ver:"0.99.4-5.etch.1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tethereal", ver:"0.99.4-5.etch.1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tshark", ver:"0.99.4-5.etch.1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-common", ver:"0.99.4-5.etch.1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-dev", ver:"0.99.4-5.etch.1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark", ver:"0.99.4-5.etch.1", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
