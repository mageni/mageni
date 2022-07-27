# OpenVAS Vulnerability Test
# $Id: deb_2061_1.nasl 8510 2018-01-24 07:57:42Z teissa $
# Description: Auto-generated from advisory DSA 2061-1 (samba)
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
tag_insight = "Jun Mao discovered that Samba, an implementation of the SMB/CIFS protocol
for Unix systems, is not properly handling certain offset values when
processing chained SMB1 packets.  This enables an unauthenticated attacker
to write to an arbitrary memory location resulting in the possibility to
execute arbitrary code with root privileges or to perform denial of service
attacks by crashing the samba daemon.


For the stable distribution (lenny), this problem has been fixed in
version 3.2.5-4lenny12.

This problem does not affect the versions in the testing (squeeze) and
unstable (sid) distribution.


We recommend that you upgrade your samba packages.";
tag_summary = "The remote host is missing an update to samba
announced via advisory DSA 2061-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202061-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.314302");
 script_version("$Revision: 8510 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-24 08:57:42 +0100 (Wed, 24 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-07-06 02:35:12 +0200 (Tue, 06 Jul 2010)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-2063");
 script_name("Debian Security Advisory DSA 2061-1 (samba)");



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
if ((res = isdpkgvuln(pkg:"samba-doc-pdf", ver:"3.2.5-4lenny12", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-doc", ver:"3.2.5-4lenny12", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-tools", ver:"3.2.5-4lenny12", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba", ver:"3.2.5-4lenny12", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsmbclient", ver:"3.2.5-4lenny12", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"smbclient", ver:"3.2.5-4lenny12", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"swat", ver:"3.2.5-4lenny12", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwbclient0", ver:"3.2.5-4lenny12", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsmbclient-dev", ver:"3.2.5-4lenny12", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpam-smbpass", ver:"3.2.5-4lenny12", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-dbg", ver:"3.2.5-4lenny12", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-common", ver:"3.2.5-4lenny12", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"smbfs", ver:"3.2.5-4lenny12", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"winbind", ver:"3.2.5-4lenny12", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
