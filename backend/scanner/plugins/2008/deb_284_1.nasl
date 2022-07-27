# OpenVAS Vulnerability Test
# $Id: deb_284_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 284-1
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
tag_insight = "The KDE team discoverd a vulnerability in the way KDE uses Ghostscript
software for processing of PostScript (PS) and PDF files.  An attacker
could provide a malicious PostScript or PDF file via mail or websites
that could lead to executing arbitrary commands under the privileges
of the user viewing the file or when the browser generates a directory
listing with thumbnails.

For the stable distribution (woody) this problem has been fixed in
version 2.2.2-6.11 of kdegraphics and associated packages.

The old stable distribution (potato) is not affected since it does not
contain KDE.

For the unstable distribution (sid) this problem will be fixed soon.

For the unofficial backport of KDE 3.1.1 to woody by Ralf Nolden on
download.kde.org, this problem has been fixed in version 3.1.1-0woody2
of kdegraphics.  Using the normal backport line for apt-get you will
get the update:

deb http://download.kde.org/stable/latest/Debian stable main

We recommend that you upgrade your kdegraphics and associated packages.";
tag_summary = "The remote host is missing an update to kdegraphics
announced via advisory DSA 284-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20284-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300804");
 script_version("$Revision: 6616 $");
 script_cve_id("CVE-2003-0204");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 284-1 (kdegraphics)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"kamera", ver:"2.2.2-6.11", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kcoloredit", ver:"2.2.2-6.11", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kfract", ver:"2.2.2-6.11", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kghostview", ver:"2.2.2-6.11", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kiconedit", ver:"2.2.2-6.11", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kooka", ver:"2.2.2-6.11", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kpaint", ver:"2.2.2-6.11", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kruler", ver:"2.2.2-6.11", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ksnapshot", ver:"2.2.2-6.11", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kview", ver:"2.2.2-6.11", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkscan-dev", ver:"2.2.2-6.11", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkscan1", ver:"2.2.2-6.11", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
