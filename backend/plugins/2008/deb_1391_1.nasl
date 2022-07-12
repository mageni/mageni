# OpenVAS Vulnerability Test
# $Id: deb_1391_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1391-1
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largerly excerpted from the referenced
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
tag_insight = "Several remote vulnerabilities have been discovered in the Icedove mail client,
an unbranded version of the Thunderbird client. The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2007-3734

Bernd Mielke, Boris Zbarsky, David Baron, Daniel Veditz, Jesse Ruderman,
Lukas Loehrer, Martijn Wargers, Mats Palmgren, Olli Pettay, Paul
Nickerson and Vladimir Sukhoy discovered crashes in the layout engine,
which might allow the execution of arbitrary code.

CVE-2007-3735

Asaf Romano, Jesse Ruderman and Igor Bukanov discovered crashes in the
javascript engine, which might allow the execution of arbitrary code.

CVE-2007-3844

moz_bug_r_a4 discovered that a regression in the handling of
about:blank windows used by addons may lead to an attacker being
able to modify the content of web sites.

CVE-2007-3845

Jesper Johansson discovered that missing sanitising of double-quotes
and spaces in URIs passed to external programs may allow an attacker
to pass arbitrary arguments to the helper program if the user is
tricked into opening a malformed web page.

CVE-2007-5339

L. David Baron, Boris Zbarsky, Georgi Guninski, Paul Nickerson, Olli Pettay,
Jesse Ruderman, Vladimir Sukhoy, Daniel Veditz, and Martijn Wargers discovered
crashes in the layout engine, which might allow the execution of arbitrary code.

CVE-2007-5340

Igor Bukanov, Eli Friedman, and Jesse Ruderman discovered crashes in the
Javascript engine, which might allow the execution of arbitrary code. Generally,
enabling Javascript in Icedove is not recommended.

The Mozilla products in the oldstable distribution (sarge) are no longer
supported with security updates.

For the stable distribution (etch) these problems have been fixed in version
1.5.0.13+1.5.0.14b.dfsg1-0etch1. Builds for hppa will be provided later.

The unstable distribution (sid) will be fixed soon.

We recommend that you upgrade your icedove packages.";
tag_summary = "The remote host is missing an update to icedove
announced via advisory DSA 1391-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201391-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300458");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:19:52 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2007-3734", "CVE-2007-3735", "CVE-2007-3844", "CVE-2007-3845", "CVE-2007-5339", "CVE-2007-5340");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1391-1 (icedove)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"1.5.0.13+1.5.0.14b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-inspector", ver:"1.5.0.13+1.5.0.14b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird-typeaheadfind", ver:"1.5.0.13+1.5.0.14b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.13+1.5.0.14b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird-dbg", ver:"1.5.0.13+1.5.0.14b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird-dev", ver:"1.5.0.13+1.5.0.14b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird-gnome-support", ver:"1.5.0.13+1.5.0.14b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird-inspector", ver:"1.5.0.13+1.5.0.14b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird-typeaheadfind", ver:"1.5.0.13+1.5.0.14b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"thunderbird", ver:"1.5.0.13+1.5.0.14b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove", ver:"1.5.0.13+1.5.0.14b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-dbg", ver:"1.5.0.13+1.5.0.14b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-dev", ver:"1.5.0.13+1.5.0.14b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-gnome-support", ver:"1.5.0.13+1.5.0.14b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-inspector", ver:"1.5.0.13+1.5.0.14b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"icedove-typeaheadfind", ver:"1.5.0.13+1.5.0.14b.dfsg1-0etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
