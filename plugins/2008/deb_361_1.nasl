# OpenVAS Vulnerability Test
# $Id: deb_361_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 361-1
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
tag_insight = "Two vulnerabilities were discovered in kdelibs:

- - CVE-2003-0459: KDE Konqueror for KDE 3.1.2 and earlier does not
remove authentication credentials from URLs of the
'user:password@host' form in the HTTP-Referer header, which could
allow remote web sites to steal the credentials for pages that link
to the sites.

- - CVE-2003-0370: Konqueror Embedded and KDE 2.2.2 and earlier does not
validate the Common Name (CN) field for X.509 Certificates, which
could allow remote attackers to spoof certificates via a
man-in-the-middle attack.

These vulnerabilities are described in the following security
advisories from KDE:

http://www.kde.org/info/security/advisory-20030729-1.txt
http://www.kde.org/info/security/advisory-20030602-1.txt

For the current stable distribution (woody) these problems have been
fixed in version 2.2.2-13.woody.8.

For the unstable distribution (sid) these problems have been fixed in
version 4:3.1.3-1.

We recommend that you update your kdelibs package.";
tag_summary = "The remote host is missing an update to kdelibs
announced via advisory DSA 361-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20361-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.301302");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:36:24 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2003-0459", "CVE-2003-0370");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 361-1 (kdelibs)");



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
if ((res = isdpkgvuln(pkg:"kdelibs3-doc", ver:"2.2.2-13.woody.8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs-dev", ver:"2.2.2-13.woody.8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs3", ver:"2.2.2-13.woody.8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs3-bin", ver:"2.2.2-13.woody.8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdelibs3-cups", ver:"2.2.2-13.woody.8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libarts", ver:"2.2.2-13.woody.8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libarts-alsa", ver:"2.2.2-13.woody.8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libarts-dev", ver:"2.2.2-13.woody.8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkmid", ver:"2.2.2-13.woody.8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkmid-alsa", ver:"2.2.2-13.woody.8", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkmid-dev", ver:"2.2.2-13.woody.8", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
