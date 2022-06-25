# OpenVAS Vulnerability Test
# $Id: deb_1840_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1840-1 (xulrunner)
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
tag_insight = "Several remote vulnerabilities have been discovered in Xulrunner, a
runtime environment for XUL applications, such as the Iceweasel web
browser. The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2009-2462

Martijn Wargers, Arno Renevier, Jesse Ruderman, Olli Pettay and Blake
Kaplan disocvered several issues in the browser engine that could
potentially lead to the execution of arbitrary code. (MFSA 2009-34)

CVE-2009-2463

monarch2020 reported an integer overflow in a base64 decoding function.
(MFSA 2009-34)

CVE-2009-2464

Christophe Charron reported a possibly exploitable crash occurring when
multiple RDF files were loaded in a XUL tree element. (MFSA 2009-34)

CVE-2009-2465

Yongqian Li reported that an unsafe memory condition could be created by
specially crafted document. (MFSA 2009-34)

CVE-2009-2466

Peter Van der Beken, Mike Shaver, Jesse Ruderman, and Carsten Book
discovered several issues in the JavaScript engine that could possibly
lead to the execution of arbitrary JavaScript. (MFSA 2009-34)

CVE-2009-2467

Attila Suszter discovered an issue related to a specially crafted Flash
object, which could be used to run arbitrary code. (MFSA 2009-35)

CVE-2009-2469

PenPal discovered that it is possible to execute arbitrary code via a
specially crafted SVG element. (MFSA 2009-37)

CVE-2009-2471

Blake Kaplan discovered a flaw in the JavaScript engine that might allow
an attacker to execute arbitrary JavaScript with chrome privileges.
(MFSA 2009-39)

CVE-2009-2472

moz_bug_r_a4 discovered an issue in the JavaScript engine that could be
used to perform cross-site scripting attacks. (MFSA 2009-40)


For the stable distribution (lenny), these problems have been fixed in
version 1.9.0.12-0lenny1.

As indicated in the Etch release notes, security support for the
Mozilla products in the oldstable distribution needed to be stopped
before the end of the regular Etch security maintenance life cycle.
You are strongly encouraged to upgrade to stable or switch to a still
supported browser.

For the testing distribution (squeeze), these problems will be fixed
soon.

For the unstable distribution (sid), these problems have been fixed in
version 1.9.0.12-1.


We recommend that you upgrade your xulrunner packages.";
tag_summary = "The remote host is missing an update to xulrunner
announced via advisory DSA 1840-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201840-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305136");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
 script_cve_id("CVE-2009-2462", "CVE-2009-2463", "CVE-2009-2464", "CVE-2009-2465", "CVE-2009-2466", "CVE-2009-2467", "CVE-2009-2469", "CVE-2009-2471", "CVE-2009-2472");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1840-1 (xulrunner)");



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
if ((res = isdpkgvuln(pkg:"libmozillainterfaces-java", ver:"1.9.0.12-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs1d-dbg", ver:"1.9.0.12-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.12-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.0.12-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-dbg", ver:"1.9.0.12-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs-dev", ver:"1.9.0.12-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs1d", ver:"1.9.0.12-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-gnome-support", ver:"1.9.0.12-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-xpcom", ver:"1.9.0.12-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"spidermonkey-bin", ver:"1.9.0.12-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
