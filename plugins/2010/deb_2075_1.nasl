# OpenVAS Vulnerability Test
# $Id: deb_2075_1.nasl 8440 2018-01-17 07:58:46Z teissa $
# Description: Auto-generated from advisory DSA 2075-1 (xulrunner)
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
runtime environment for XUL applications. The Common Vulnerabilities
and Exposures project identifies the following problems:

CVE-2010-0182

Wladimir Palant discovered that security checks in XML processing
were insufficiently enforced.

CVE-2010-0654

Chris Evans discovered that insecure CSS handling could lead to
reading data across domain boundaries.

CVE-2010-1205

Aki Helin discovered a buffer overflow in the internal copy of
libpng, which could lead to the execution of arbitrary code.

CVE-2010-1208

regenrecht discovered that incorrect memory handling in DOM
parsing could lead to the execution of arbitrary code.

CVE-2010-1211

Jesse Ruderman, Ehsan Akhgari, Mats Palmgren, Igor Bukanov, Gary
Kwong, Tobias Markus and Daniel Holbert discovered crashes in the
layout engine, which might allow the execution of arbitrary code.

CVE-2010-1214

JS3 discovered an integer overflow in the plugin code, which
could lead to the execution of arbitrary code.

CVE-2010-2751

Jordi Chancel discovered that the location could be spoofed to
appear like a secured page.

CVE-2010-2753

regenrecht discovered that incorrect memory handling in XUL
parsing could lead to the execution of arbitrary code.

CVE-2010-2754

Soroush Dalili discovered an information leak in script processing.


For the stable distribution (lenny), these problems have been fixed in
version 1.9.0.19-3.

For the unstable distribution (sid), these problems have been fixed in
version 1.9.1.11-1.

For the experimental distribution, these problems have been fixed in
version 1.9.2.7-1.

We recommend that you upgrade your xulrunner packages.";
tag_summary = "The remote host is missing an update to xulrunner
announced via advisory DSA 2075-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202075-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.312882");
 script_version("$Revision: 8440 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-08-21 08:54:16 +0200 (Sat, 21 Aug 2010)");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2010-0182", "CVE-2010-0654", "CVE-2010-1205", "CVE-2010-1208", "CVE-2010-1211", "CVE-2010-1214", "CVE-2010-2751", "CVE-2010-2753", "CVE-2010-2754");
 script_name("Debian Security Advisory DSA 2075-1 (xulrunner)");



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
if ((res = isdpkgvuln(pkg:"libmozillainterfaces-java", ver:"1.9.0.19-3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-xpcom", ver:"1.9.0.19-3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs1d", ver:"1.9.0.19-3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"spidermonkey-bin", ver:"1.9.0.19-3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-dbg", ver:"1.9.0.19-3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.19-3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs-dev", ver:"1.9.0.19-3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-gnome-support", ver:"1.9.0.19-3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs1d-dbg", ver:"1.9.0.19-3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.0.19-3", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
