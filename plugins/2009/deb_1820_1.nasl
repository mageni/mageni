# OpenVAS Vulnerability Test
# $Id: deb_1820_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1820-1 (xulrunner)
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

CVE-2009-1392

Several issues in the browser engine have been discovered, which can
result in the execution of arbitrary code. (MFSA 2009-24)

CVE-2009-1832

It is possible to execute arbitrary code via vectors involving double
frame construction. (MFSA 2009-24)

CVE-2009-1833

Jesse Ruderman and Adam Hauner discovered a problem in the JavaScript
engine, which could lead to the execution of arbitrary code.
(MFSA 2009-24)

CVE-2009-1834

Pavel Cvrcek discovered a potential issue leading to a spoofing attack
on the location bar related to certain invalid unicode characters.
(MFSA 2009-25)

CVE-2009-1835

Gregory Fleischer discovered that it is possible to read arbitrary
cookies via a crafted HTML document. (MFSA 2009-26)

CVE-2009-1836

Shuo Chen, Ziqing Mao, Yi-Min Wang and Ming Zhang reported a potential
man-in-the-middle attack, when using a proxy due to insufficient checks
on a certain proxy response. (MFSA 2009-27)

CVE-2009-1837

Jakob Balle and Carsten Eiram reported a race condition in the
NPObjWrapper_NewResolve function that can be used to execute arbitrary
code. (MFSA 2009-28)

CVE-2009-1838

moz_bug_r_a4 discovered that it is possible to execute arbitrary
JavaScript with chrome privileges due to an error in the
garbage-collection implementation. (MFSA 2009-29)

CVE-2009-1839

Adam Barth and Collin Jackson reported a potential privilege escalation
when loading a file::resource via the location bar. (MFSA 2009-30)

CVE-2009-1840

Wladimir Palant discovered that it is possible to bypass access
restrictions due to a lack of content policy check, when loading a
script file into a XUL document. (MFSA 2009-31)

CVE-2009-1841

moz_bug_r_a4 reported that it is possible for scripts from page content
to run with elevated privileges and thus potentially executing arbitrary
code with the object's chrome privileges. (MFSA 2009-32)



For the stable distribution (lenny), these problems have been fixed in
version 1.9.0.11-0lenny1.

As indicated in the Etch release notes, security support for the
Mozilla products in the oldstable distribution needed to be stopped
before the end of the regular Etch security maintenance life cycle.
You are strongly encouraged to upgrade to stable or switch to a still
supported browser.

For the testing distribution (squeeze), these problems will be fixed
soon.

For the unstable distribution (sid), these problems have been fixed in
version 1.9.0.11-1.

We recommend that you upgrade your xulrunner packages.";
tag_summary = "The remote host is missing an update to xulrunner
announced via advisory DSA 1820-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201820-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309727");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-06-23 15:49:15 +0200 (Tue, 23 Jun 2009)");
 script_cve_id("CVE-2009-1392", "CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1834", "CVE-2009-1835", "CVE-2009-1836", "CVE-2009-1837", "CVE-2009-1838", "CVE-2009-1839", "CVE-2009-1840", "CVE-2009-1841");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1820-1 (xulrunner)");



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
if ((res = isdpkgvuln(pkg:"libmozillainterfaces-java", ver:"1.9.0.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs-dev", ver:"1.9.0.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-gnome-support", ver:"1.9.0.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs1d", ver:"1.9.0.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-dbg", ver:"1.9.0.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.0.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"spidermonkey-bin", ver:"1.9.0.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs1d-dbg", ver:"1.9.0.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-xpcom", ver:"1.9.0.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.11-0lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
