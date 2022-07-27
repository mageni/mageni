# OpenVAS Vulnerability Test
# $Id: deb_2027_1.nasl 8244 2017-12-25 07:29:28Z teissa $
# Description: Auto-generated from advisory DSA 2027-1 (xulrunner)
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
tag_insight = "Several remote vulnerabilities have been discovered in Xulrunner, a
runtime environment for XUL applications, such as the Iceweasel web
browser. The Common Vulnerabilities and Exposures project identifies
the following problems:

CVE-2010-0174

Jesse Ruderman and Ehsan Akhgari discovered crashes in the layout
engine, which might allow the execution of arbitrary code.

CVE-2010-0175

It was discovered that incorrect memory handling in the XUL event
handler might allow the execution of arbitrary code.

CVE-2010-0176

It was discovered that incorrect memory handling in the XUL event
handler might allow the execution of arbitrary code.

CVE-2010-0177

It was discovered that incorrect memory handling in the plugin code
might allow the execution of arbitrary code.

CVE-2010-0178

Paul Stone discovered that forced drag-and-drop events could lead to
Chrome privilege escalation.

CVE-2010-0179

It was discovered that a programming error in the XMLHttpRequestSpy
module could lead to the execution of arbitrary code.


For the stable distribution (lenny), these problems have been fixed in
version 1.9.0.19-1.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your xulrunner packages.";
tag_summary = "The remote host is missing an update to xulrunner
announced via advisory DSA 2027-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202027-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.314394");
 script_version("$Revision: 8244 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-25 08:29:28 +0100 (Mon, 25 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-04-21 03:31:17 +0200 (Wed, 21 Apr 2010)");
 script_cve_id("CVE-2010-0174", "CVE-2010-0175", "CVE-2010-0176", "CVE-2010-0177", "CVE-2010-0178", "CVE-2010-0179");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 2027-1 (xulrunner)");



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
if ((res = isdpkgvuln(pkg:"libmozillainterfaces-java", ver:"1.9.0.19-1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.19-1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs-dev", ver:"1.9.0.19-1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs1d", ver:"1.9.0.19-1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-dbg", ver:"1.9.0.19-1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-xpcom", ver:"1.9.0.19-1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-gnome-support", ver:"1.9.0.19-1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.0.19-1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"spidermonkey-bin", ver:"1.9.0.19-1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs1d-dbg", ver:"1.9.0.19-1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
