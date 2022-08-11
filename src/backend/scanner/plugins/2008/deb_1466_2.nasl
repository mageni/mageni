# OpenVAS Vulnerability Test
# $Id: deb_1466_2.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1466-2 (xorg-server, libxfont, xfree86)
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
tag_insight = "The X.org fix for CVE-2007-6429 introduced a regression in the MIT-SHM
extension, which prevented the start of a few applications. This update
fixes this problem and also references the patch for CVE-2008-0006,
which was included in the previous update, but not mentioned in the
advisory text.

Several local vulnerabilities have been discovered in the X.Org X
server. The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2007-5760

regenrecht discovered that missing input sanitising within
the XFree86-Misc extension may lead to local privilege escalation.

CVE-2007-5958

It was discovered that error messages of security policy file
handling may lead to a minor information leak disclosing the
existence of files otherwise unaccessible to the user.

CVE-2007-6427

regenrecht discovered that missing input sanitising within
the XInput-Misc extension may lead to local privilege escalation.

CVE-2007-6428

regenrecht discovered that missing input sanitising within
the TOG-CUP extension may lead to disclosure of memory contents.

CVE-2007-6429

regenrecht discovered that integer overflows in the EVI
and MIT-SHM extensions may lead to local privilege escalation.

CVE-2008-0006

It was discovered that insufficient validation of PCF fonts could lead
to local privilege escalation.

For the unstable distribution (sid), this problem has been fixed in
version 2:1.4.1~git20080118-1 of xorg-server and version 1:1.3.1-2
of libxfont.

For the stable distribution (etch), this problem has been fixed in
version 1.1.1-21etch3 or xorg-server and 1.2.2-2.etch1 of libxfont.

For the oldstable distribution (etch), this problem has been fixed in
version 4.3.0.dfsg.1-14sarge6 of xfree86.

We recommend that you upgrade your libxfont abd xorg-server packages.";
tag_summary = "The remote host is missing an update to xorg-server, libxfont, xfree86
announced via advisory DSA 1466-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201466-2";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303799");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-31 16:11:48 +0100 (Thu, 31 Jan 2008)");
 script_cve_id("CVE-2007-5760", "CVE-2007-5958", "CVE-2007-6427", "CVE-2007-6428", "CVE-2007-6429", "CVE-2008-0006");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1466-2 (xorg-server, libxfont, xfree86)");



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
if ((res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"1.1.1-21etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-xorg-dev", ver:"1.1.1-21etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xnest", ver:"1.1.1-21etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xvfb", ver:"1.1.1-21etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xdmx", ver:"1.1.1-21etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xdmx-tools", ver:"1.1.1-21etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xserver-xephyr", ver:"1.1.1-21etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
