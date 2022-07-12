# OpenVAS Vulnerability Test
# $Id: deb_1671_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1671-1 (iceweasel)
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
tag_insight = "Several remote vulnerabilities have been discovered in the Iceweasel
webbrowser, an unbranded version of the Firefox browser. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-0017

Justin Schuh discovered that a buffer overflow in the http-index-format
parser could lead to arbitrary code execution.

CVE-2008-4582

Liu Die Yu discovered an information leak through local shortcut
files.

CVE-2008-5012

Georgi Guninski, Michal Zalewski and Chris Evan discovered that
the canvas element could be used to bypass same-origin
restrictions.

CVE-2008-5013

It was discovered that insufficient checks in the Flash plugin glue
code could lead to arbitrary code execution.

CVE-2008-5014

Jesse Ruderman discovered that a programming error in the
window.__proto__.__proto__ object could lead to arbitrary code
execution.

CVE-2008-5017

It was discovered that crashes in the layout engine could lead to
arbitrary code execution.

CVE-2008-5018

It was discovered that crashes in the Javascript engine could lead to
arbitrary code execution.

CVE-2008-5021

It was discovered that a crash in the nsFrameManager might lead to
the execution of arbitrary code.

CVE-2008-5022

moz_bug_r_a4 discovered that the same-origin check in
nsXMLHttpRequest::NotifyEventListeners() could be bypassed.

CVE-2008-5023

Collin Jackson discovered that the -moz-binding property bypasses
security checks on codebase principals.

CVE-2008-5024

Chris Evans discovered that quote characters were improperly
escaped in the default namespace of E4X documents.

For the stable distribution (etch), these problems have been fixed in
version 2.0.0.18-0etch1.

For the upcoming stable distribution (lenny) and the unstable distribution
(sid), these problems have been fixed in version 3.0.4-1 of iceweasel
and version 1.9.0.4-1 of xulrunner. Packages for arm and mips will be
provided soon.

We recommend that you upgrade your iceweasel package.";
tag_summary = "The remote host is missing an update to iceweasel
announced via advisory DSA 1671-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201671-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300831");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-12-03 18:25:22 +0100 (Wed, 03 Dec 2008)");
 script_cve_id("CVE-2008-0017", "CVE-2008-4582", "CVE-2008-5012", "CVE-2008-5013", "CVE-2008-5014", "CVE-2008-5017", "CVE-2008-5018", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5023", "CVE-2008-5024");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1671-1 (iceweasel)");



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
if ((res = isdpkgvuln(pkg:"mozilla-firefox-gnome-support", ver:"2.0.0.18-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"2.0.0.18-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"2.0.0.18-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.18-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-firefox", ver:"2.0.0.18-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceweasel-dom-inspector", ver:"2.0.0.18-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-firefox-dom-inspector", ver:"2.0.0.18-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceweasel", ver:"2.0.0.18-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceweasel-dbg", ver:"2.0.0.18-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceweasel-gnome-support", ver:"2.0.0.18-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
