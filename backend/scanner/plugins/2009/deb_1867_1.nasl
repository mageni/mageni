# OpenVAS Vulnerability Test
# $Id: deb_1867_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1867-1 (kdelibs)
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
tag_insight = "Several security issues have been discovered in kdelibs, core libraries
from the official KDE release. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2009-1690

It was discovered that there is a use-after-free flaw in handling
certain DOM event handlers. This could lead to the execution of
arbitrary code, when visiting a malicious website.

CVE-2009-1698

It was discovered that there could be an uninitialised pointer when
handling a Cascading Style Sheets (CSS) attr function call. This could
lead to the execution of arbitrary code, when visiting a malicious
website.

CVE-2009-1687

It was discovered that the JavaScript garbage collector does not handle
allocation failures properly, which could lead to the execution of
arbitrary code when visiting a malicious website.


For the stable distribution (lenny), these problems have been fixed in
version 4:3.5.10.dfsg.1-0lenny2.

For the oldstable distribution (etch), these problems have been fixed
in version 4:3.5.5a.dfsg.1-8etch2.

For the testing distribution (squeeze) and the unstable distribution
(sid), these problems will be fixed soon.


We recommend that you upgrade your kdelibs packages.";
tag_summary = "The remote host is missing an update to kdelibs
announced via advisory DSA 1867-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201867-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.307659");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-09-02 04:58:39 +0200 (Wed, 02 Sep 2009)");
 script_cve_id("CVE-2009-1690", "CVE-2009-1698", "CVE-2009-1687");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1867-1 (kdelibs)");



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
if ((res = isdpkgvuln(pkg:"kdelibs", ver:"3.5.5a.dfsg.1-8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs-data", ver:"3.5.5a.dfsg.1-8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs4-doc", ver:"3.5.5a.dfsg.1-8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs4c2a", ver:"3.5.5a.dfsg.1-8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs4-dev", ver:"3.5.5a.dfsg.1-8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs-dbg", ver:"3.5.5a.dfsg.1-8etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs", ver:"3.5.10.dfsg.1-0lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs-data", ver:"3.5.10.dfsg.1-0lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs4-doc", ver:"3.5.10.dfsg.1-0lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs-dbg", ver:"3.5.10.dfsg.1-0lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs4-dev", ver:"3.5.10.dfsg.1-0lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs4c2a", ver:"3.5.10.dfsg.1-0lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
