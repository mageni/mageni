# OpenVAS Vulnerability Test
# $Id: deb_204_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 204-1
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
tag_insight = "The KDE team has discovered a vulnerability in the support for various
network protocols via the KIO The implementation of the rlogin and
protocol allows a carefully crafted URL in an HTML page, HTML email or
other KIO-enabled application to execute arbitrary commands on the
system using the victim's account on the vulnerable machine.

This problem has been fixed by disabling rlogin and telnet in version
2.2.2-13.woody.5 for the current stable distribution (woody) and in
version 2.2.2-14.1 for the unstable distribution (sid).  The old
stable distribution (potato) is not affected since it doesn't contain
KDE.

This problem has been fixed by disabling rlogin and telnet in version
2.2.2-13.woody.5 for the current stable distribution (woody).  The old
stable distribution (potato) is not affected since it doesn't contain
KDE.  A correction for the package in the unstable distribution (sid)
is not yet available.

We recommend that you upgrade your kdelibs3 package immediately.";
tag_summary = "The remote host is missing an update to kdelibs
announced via advisory DSA 204-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20204-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300531");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2002-1281", "CVE-2002-1282");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 204-1 (kdelibs)");



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
if ((res = isdpkgvuln(pkg:"kdelibs3-doc", ver:"2.2.2-13.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs-dev", ver:"2.2.2-13.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs3", ver:"2.2.2-13.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs3-bin", ver:"2.2.2-13.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs3-cups", ver:"2.2.2-13.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libarts", ver:"2.2.2-13.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libarts-alsa", ver:"2.2.2-13.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libarts-dev", ver:"2.2.2-13.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkmid", ver:"2.2.2-13.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkmid-alsa", ver:"2.2.2-13.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkmid-dev", ver:"2.2.2-13.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
