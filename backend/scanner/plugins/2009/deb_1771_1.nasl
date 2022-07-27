# OpenVAS Vulnerability Test
# $Id: deb_1771_1.nasl 6615 2017-07-07 12:09:52Z cfischer $
# Description: Auto-generated from advisory DSA 1771-1 (clamav)
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
tag_insight = "Several vulnerabilities have been discovered in the ClamAV anti-virus
toolkit:

CVE-2008-6680

Attackers can cayse a denial of service (crash) via a crafted EXE
file that triggers a divide-by-zero error.

CVE-2009-1270

Attackers can cause a denial of service (infinite loop) via a
crafted tar file that causes (1) clamd and (2) clamscan to hang.

(no CVE Id yet)

Attackers can cause a denial of service (crash) via a crafted EXE
file that crashes the UPack unpacker.

For the old stable distribution (etch), these problems have been fixed
in version 0.90.1dfsg-4etch19.

For the stable distribution (lenny), these problems have been fixed in
version 0.94.dfsg.2-1lenny2.

For the unstable distribution (sid), these problems have been fixed in
version 0.95.1+dfsg-1.

We recommend that you upgrade your clamav packages.";
tag_summary = "The remote host is missing an update to clamav
announced via advisory DSA 1771-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201771-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.308367");
 script_version("$Revision: 6615 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:09:52 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-04-20 23:45:17 +0200 (Mon, 20 Apr 2009)");
 script_cve_id("CVE-2008-6680", "CVE-2009-1270");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_name("Debian Security Advisory DSA 1771-1 (clamav)");



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
if ((res = isdpkgvuln(pkg:"clamav-base", ver:"0.90.1dfsg-4etch19", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav-docs", ver:"0.90.1dfsg-4etch19", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav-testfiles", ver:"0.90.1dfsg-4etch19", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav", ver:"0.90.1dfsg-4etch19", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav-dbg", ver:"0.90.1dfsg-4etch19", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav-freshclam", ver:"0.90.1dfsg-4etch19", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav-milter", ver:"0.90.1dfsg-4etch19", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libclamav2", ver:"0.90.1dfsg-4etch19", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libclamav-dev", ver:"0.90.1dfsg-4etch19", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav-daemon", ver:"0.90.1dfsg-4etch19", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav-docs", ver:"0.94.dfsg.2-1lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav-testfiles", ver:"0.94.dfsg.2-1lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav-base", ver:"0.94.dfsg.2-1lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libclamav5", ver:"0.94.dfsg.2-1lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav-dbg", ver:"0.94.dfsg.2-1lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libclamav-dev", ver:"0.94.dfsg.2-1lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav-freshclam", ver:"0.94.dfsg.2-1lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav-daemon", ver:"0.94.dfsg.2-1lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav", ver:"0.94.dfsg.2-1lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"clamav-milter", ver:"0.94.dfsg.2-1lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
