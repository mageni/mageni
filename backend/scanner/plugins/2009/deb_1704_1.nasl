# OpenVAS Vulnerability Test
# $Id: deb_1704_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1704-1 (xulrunner)
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
runtime environment for XUL applications. The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2008-5500

Jesse Ruderman  discovered that the layout engine is vulnerable to
DoS attacks that might trigger memory corruption and an integer
overflow. (MFSA 2008-60)

CVE-2008-5503

Boris Zbarsky discovered that an information disclosure attack could
be performed via XBL bindings. (MFSA 2008-61)

CVE-2008-5506

Marius Schilder discovered that it is possible to obtain sensible
data via a XMLHttpRequest. (MFSA 2008-64)

CVE-2008-5507

Chris Evans discovered that it is possible to obtain sensible data
via a JavaScript URL. (MFSA 2008-65)

CVE-2008-5508

Chip Salzenberg discovered possible phishing attacks via URLs with
leading whitespaces or control characters. (MFSA 2008-66)

CVE-2008-5511

It was discovered that it is possible to perform cross-site scripting
attacks via an XBL binding to an unloaded document. (MFSA 2008-68)

CVE-2008-5512

It was discovered that it is possible to run arbitrary JavaScript
with chrome privileges via unknown vectors. (MFSA 2008-68)

For the stable distribution (etch) these problems have been fixed in
version 1.8.0.15~pre080614i-0etch1.

For the testing distribution (lenny) and the unstable distribution (sid)
these problems have been fixed in version 1.9.0.5-1.

We recommend that you upgrade your xulrunner packages.";
tag_summary = "The remote host is missing an update to xulrunner
announced via advisory DSA 1704-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201704-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.306666");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-01-20 22:42:09 +0100 (Tue, 20 Jan 2009)");
 script_cve_id("CVE-2008-5500", "CVE-2008-5503", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5511", "CVE-2008-5512");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1704-1 (xulrunner)");



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
if ((res = isdpkgvuln(pkg:"libnss3-dev", ver:"1.8.0.15~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxul-common", ver:"1.8.0.15~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs-dev", ver:"1.8.0.15~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxul-dev", ver:"1.8.0.15~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsmjs1", ver:"1.8.0.15~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozillainterfaces-java", ver:"1.8.0.15~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnspr4-dev", ver:"1.8.0.15~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsmjs-dev", ver:"1.8.0.15~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxul0d-dbg", ver:"1.8.0.15~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnss3-0d", ver:"1.8.0.15~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"spidermonkey-bin", ver:"1.8.0.15~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnss3-tools", ver:"1.8.0.15~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnspr4-0d-dbg", ver:"1.8.0.15~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner", ver:"1.8.0.15~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-gnome-support", ver:"1.8.0.15~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-xpcom", ver:"1.8.0.15~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxul0d", ver:"1.8.0.15~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnspr4-0d", ver:"1.8.0.15~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs0d", ver:"1.8.0.15~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnss3-0d-dbg", ver:"1.8.0.15~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs0d-dbg", ver:"1.8.0.15~pre080614i-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
