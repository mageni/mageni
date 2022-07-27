# OpenVAS Vulnerability Test
# $Id: deb_1549_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1549-1 (clamav)
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
tag_insight = "Several remote vulnerabilities have been discovered in the Clam anti-virus
toolkit. The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2008-0314

Damian Put discovered that a buffer overflow in the handler for
PeSpin binaries may lead to the execution of arbitrary code.

CVE-2008-1100

Alin Rad Pop discovered that a buffer overflow in the handler for
Upack PE binaries may lead to the execution of arbitrary code.

no CVE yet

Damian Put and Thomas Pollet discovered that a buffer overflow in
the handler for WWPack-compressed PE binaries may lead to the
execution of arbitrary code.

For the stable distribution (etch) these problems have been fixed
in version 0.90.1-3etch11.

For the unstable distribution (sid) these problems have been fixed in
version 0.92.1~dfsg2-1

We recommend that you upgrade your clamav packages.";
tag_summary = "The remote host is missing an update to clamav
announced via advisory DSA 1549-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201549-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302400");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-04-21 20:40:14 +0200 (Mon, 21 Apr 2008)");
 script_cve_id("CVE-2008-0314", "CVE-2008-1100");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1549-1 (clamav)");



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
if ((res = isdpkgvuln(pkg:"clamav-testfiles", ver:"0.90.1dfsg-3etch11", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav-base", ver:"0.90.1dfsg-3etch11", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav-docs", ver:"0.90.1dfsg-3etch11", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libclamav2", ver:"0.90.1dfsg-3etch11", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav", ver:"0.90.1dfsg-3etch11", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav-freshclam", ver:"0.90.1dfsg-3etch11", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav-daemon", ver:"0.90.1dfsg-3etch11", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav-dbg", ver:"0.90.1dfsg-3etch11", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libclamav-dev", ver:"0.90.1dfsg-3etch11", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav-milter", ver:"0.90.1dfsg-3etch11", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
