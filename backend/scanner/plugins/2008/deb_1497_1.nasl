# OpenVAS Vulnerability Test
# $Id: deb_1497_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1497-1 (clamav)
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
tag_insight = "Several vulnerabilities have been discovered in the Clam anti-virus
toolkit, which may lead to the execution of arbitrary or local denial
of service. The Common Vulnerabilities and Exposures project identifies
the following problems:

CVE-2007-6595

It was discovered that temporary files are created insecurely,
which may result in local denial of service by overwriting files.

CVE-2008-0318

Silvio Cesare discovered an integer overflow in the parser for PE
headers.


For the stable distribution (etch), these problems have been fixed in
version 0.90.1dfsg-3etch10. In addition to these fixes, this update
also incorporates changes from the upcoming point release of the
stable distribution (non-free RAR handling code was removed).

The version of clamav in the old stable distribution (sarge) is no
longer supported with security updates.

We recommend that you upgrade your clamav packages.";
tag_summary = "The remote host is missing an update to clamav
announced via advisory DSA 1497-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201497-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300355");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-02-28 02:09:28 +0100 (Thu, 28 Feb 2008)");
 script_cve_id("CVE-2007-6595", "CVE-2008-0318");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1497-1 (clamav)");



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
if ((res = isdpkgvuln(pkg:"clamav-testfiles", ver:"0.90.1dfsg-3etch10", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav-base", ver:"0.90.1dfsg-3etch10", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav-docs", ver:"0.90.1dfsg-3etch10", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libclamav-dev", ver:"0.90.1dfsg-3etch10", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libclamav2", ver:"0.90.1dfsg-3etch10", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav", ver:"0.90.1dfsg-3etch10", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav-freshclam", ver:"0.90.1dfsg-3etch10", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav-dbg", ver:"0.90.1dfsg-3etch10", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav-milter", ver:"0.90.1dfsg-3etch10", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav-daemon", ver:"0.90.1dfsg-3etch10", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
