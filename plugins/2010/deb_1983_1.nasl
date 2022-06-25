# OpenVAS Vulnerability Test
# $Id: deb_1983_1.nasl 8457 2018-01-18 07:58:32Z teissa $
# Description: Auto-generated from advisory DSA 1983-1 (wireshark)
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
tag_insight = "Several remote vulnerabilities have been discovered in the Wireshark
network traffic analyzer, which may lead to the execution of arbitrary
code or denial of service. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2009-4337

A NULL pointer dereference was found in the SMB/SMB2 dissectors.

CVE-2010-0304

Several buffer overflows were found in the LWRES dissector.

For the stable distribution (lenny), this problem has been fixed in
version 1.0.2-3+lenny8.

For the unstable distribution (sid) these problems have been fixed in
version 1.2.6-1.

We recommend that you upgrade your Wireshark packages.";
tag_summary = "The remote host is missing an update to wireshark
announced via advisory DSA 1983-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201983-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.313985");
 script_version("$Revision: 8457 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-02-10 21:51:26 +0100 (Wed, 10 Feb 2010)");
 script_cve_id("CVE-2009-4337", "CVE-2010-0304");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1983-1 (wireshark)");



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
if ((res = isdpkgvuln(pkg:"wireshark-dev", ver:"1.0.2-3+lenny8", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-common", ver:"1.0.2-3+lenny8", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark", ver:"1.0.2-3+lenny8", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tshark", ver:"1.0.2-3+lenny8", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
