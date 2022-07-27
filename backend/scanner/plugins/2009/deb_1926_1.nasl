# OpenVAS Vulnerability Test
# $Id: deb_1926_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1926-1 (typo3-src)
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
tag_insight = "Several remote vulnerabilities have been discovered in the TYPO3 web
content management framework. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2009-3628

The Backend subcomponent allows remote authenticated users to
determine an encryption key via crafted input to a form field.

CVE-2009-3629

Multiple cross-site scripting (XSS) vulnerabilities in the
Backend subcomponent allow remote authenticated users to inject
arbitrary web script or HTML.

CVE-2009-3630

The Backend subcomponent allows remote authenticated users to
place arbitrary web sites in TYPO3 backend framesets via
crafted parameters.

CVE-2009-3631

The Backend subcomponent, when the DAM extension or ftp upload
is enabled, allows remote authenticated users to execute
arbitrary commands via shell metacharacters in a filename.

CVE-2009-3632

SQL injection vulnerability in the traditional frontend editing
feature in the Frontend Editing subcomponent allows remote
authenticated users to execute arbitrary SQL commands.

CVE-2009-3633

Cross-site scripting (XSS) vulnerability in allows remote
attackers to inject arbitrary web script.

CVE-2009-3634

Cross-site scripting (XSS) vulnerability in the Frontend Login Box
(aka felogin) subcomponent allows remote attackers to inject
arbitrary web script or HTML.

CVE-2009-3635

The Install Tool subcomponent allows remote attackers to gain access
by using only the password's md5 hash as a credential.

CVE-2009-3636

Cross-site scripting (XSS) vulnerability in the Install Tool
subcomponen allows remote attackers to inject arbitrary web script
or HTML.

For the old stable distribution (etch), these problems have been fixed
in version 4.0.2+debian-9.

For the stable distribution (lenny), these problems have been fixed in
version 4.2.5-1+lenny2.

For the unstable distribution (sid), these problems have been fixed in
version 4.2.10-1.

We recommend that you upgrade your typo3-src package.";
tag_summary = "The remote host is missing an update to typo3-src
announced via advisory DSA 1926-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201926-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.310724");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-11-11 15:56:44 +0100 (Wed, 11 Nov 2009)");
 script_cve_id("CVE-2009-3628", "CVE-2009-3629", "CVE-2009-3630", "CVE-2009-3631", "CVE-2009-3632", "CVE-2009-3633", "CVE-2009-3634", "CVE-2009-3635", "CVE-2009-3636");
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1926-1 (typo3-src)");



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
if ((res = isdpkgvuln(pkg:"typo3-src-4.0", ver:"4.0.2+debian-9", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3", ver:"4.0.2+debian-9", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-src-4.2", ver:"4.2.5-1+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3", ver:"4.2.5-1+lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
