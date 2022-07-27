# OpenVAS Vulnerability Test
# $Id: deb_2064_1.nasl 8485 2018-01-22 07:57:57Z teissa $
# Description: Auto-generated from advisory DSA 2064-1 (xulrunner)
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

CVE-2010-0183

wushi discovered that incorrect pointer handling in the frame
processing code could lead to the execution of arbitrary code.

CVE-2010-1196

Nils discovered that an integer overflow in DOM node parsing could
lead to the execution of arbitrary code.

CVE-2010-1197

Ilja von Sprundel discovered that incorrect parsing of
Content-Disposition headers could lead to cross-site scripting.

CVE-2010-1198

Microsoft engineers discovered that incorrect memory handling in the
interaction of browser plugins could lead to the execution of
arbitrary code.

CVE-2010-1199

Martin Barbella discovered that an integer overflow in XSLT node
parsing could lead to the execution of arbitrary code.

CVE-2010-1200

Olli Pettay, Martijn Wargers, Justin Lebar, Jesse Ruderman, Ben
Turner, Jonathan Kew and David Humphrey discovered crashes in the
layout engine, which might allow the execution of arbitrary code.

CVE-2010-1201

boardraider and stedenon discovered crashes in the layout engine,
which might allow the execution of arbitrary code.

CVE-2010-1202

Bob Clary, Igor Bukanov, Gary Kwong and Andreas Gal discovered crashes
in the Javascript engine, which might allow the execution of arbitrary
code.


For the stable distribution (lenny), these problems have been fixed in
version 1.9.0.19-2.

For the unstable distribution (sid), these problems have been fixed in
version 1.9.1.10-1

For the experimental distribution, these problems have been fixed in
version 1.9.2.4-1.

We recommend that you upgrade your xulrunner packages.";
tag_summary = "The remote host is missing an update to xulrunner
announced via advisory DSA 2064-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202064-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.314199");
 script_version("$Revision: 8485 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-22 08:57:57 +0100 (Mon, 22 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-07-06 02:35:12 +0200 (Tue, 06 Jul 2010)");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2010-0183", "CVE-2010-1196", "CVE-2010-1197", "CVE-2010-1198", "CVE-2010-1199", "CVE-2010-1200", "CVE-2010-1201", "CVE-2010-1202");
 script_name("Debian Security Advisory DSA 2064-1 (xulrunner)");



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
if ((res = isdpkgvuln(pkg:"libmozillainterfaces-java", ver:"1.9.0.19-2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9", ver:"1.9.0.19-2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs-dev", ver:"1.9.0.19-2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs1d", ver:"1.9.0.19-2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs1d-dbg", ver:"1.9.0.19-2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-xpcom", ver:"1.9.0.19-2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-gnome-support", ver:"1.9.0.19-2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9-dbg", ver:"1.9.0.19-2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"spidermonkey-bin", ver:"1.9.0.19-2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.0.19-2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
