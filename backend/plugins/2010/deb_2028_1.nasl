# OpenVAS Vulnerability Test
# $Id: deb_2028_1.nasl 8314 2018-01-08 08:01:01Z teissa $
# Description: Auto-generated from advisory DSA 2028-1 (xpdf)
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
tag_insight = "Several vulnerabilities have been identified in xpdf, a suite of tools for
viewing and converting Portable Document Format (PDF) files.

The Common Vulnerabilities and Exposures project identifies the following
problems:

CVE-2009-1188 and CVE-2009-3603

Integer overflow in SplashBitmap::SplashBitmap which might allow remote
attackers to execute arbitrary code or an application crash via a crafted
PDF document.

CVE-2009-3604

NULL pointer dereference or heap-based buffer overflow in
Splash::drawImage which might allow remote attackers to cause a denial
of service (application crash) or possibly execute arbitrary code via
a crafted PDF document.

CVE-2009-3606

Integer overflow in the PSOutputDev::doImageL1Sep which might allow
remote attackers to execute arbitrary code via a crafted PDF document.

CVE-2009-3608

Integer overflow in the ObjectStream::ObjectStream which might allow
remote attackers to execute arbitrary code via a crafted PDF document.

CVE-2009-3609

Integer overflow in the ImageStream::ImageStream which might allow
remote attackers to cause a denial of service via a crafted PDF
document.


For the stable distribution (lenny), this problem has been fixed in
version 3.02-1.4+lenny2.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 3.02-2.";
tag_summary = "The remote host is missing an update to xpdf
announced via advisory DSA 2028-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202028-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.314406");
 script_version("$Revision: 8314 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-08 09:01:01 +0100 (Mon, 08 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-04-21 03:31:17 +0200 (Wed, 21 Apr 2010)");
 script_cve_id("CVE-2009-1188", "CVE-2009-3603", "CVE-2009-3604", "CVE-2009-3606", "CVE-2009-3608", "CVE-2009-3609");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 2028-1 (xpdf)");



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
if ((res = isdpkgvuln(pkg:"xpdf", ver:"3.02-1.4+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xpdf-common", ver:"3.02-1.4+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xpdf-reader", ver:"3.02-1.4+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xpdf-utils", ver:"3.02-1.4+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
