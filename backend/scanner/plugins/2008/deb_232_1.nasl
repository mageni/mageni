# OpenVAS Vulnerability Test
# $Id: deb_232_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 232-1
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
tag_insight = "Multiple vulnerabilities were discovered in the Common Unix Printing
System (CUPS).  Several of these issues represent the potential for a
remote compromise or denial of service.  The Common Vulnerabilities
and Exposures project identifies the following problems:

. CVE-2002-1383: Multiple integer overflows allow a remote attacker
to execute arbitrary code via the CUPSd HTTP interface and the
image handling code in CUPS filters.

. CVE-2002-1366: Race conditions in connection with /etc/cups/certs/
allow local users with lp privileges to create or overwrite
arbitrary files.  This is not present in the potato version.

. CVE-2002-1367: This vulnerabilities allows a remote attacker to add
printers without authentication via a certain UDP packet, which can
then be used to perform unauthorized activities such as stealing
the local root certificate for the administration server via a
'need authorization' page.

. CVE-2002-1368: Negative lengths fed into memcpy() can cause a
denial of service and possibly execute arbitrary code.

. CVE-2002-1369: An unsafe strncat() function call processing the
options string allows a remote attacker to execute arbitrary code
via a buffer overflow.

. CVE-2002-1371: Zero width images allows a remote attacker to
execute arbitrary code via modified chunk headers.

. CVE-2002-1372: CUPS does not properly check the return values of
various file and socket operations, which could allow a remote
attacker to cause a denial of service.

. CVE-2002-1384: The cupsys package contains some code from the xpdf
package, used to convert PDF files for printing, which contains an
exploitable integer overflow bug.  This is not present in the
potato version.

Even though we tried very hard to fix all problems in the packages for
potato as well, the packages may still contain other security related
problems.  Hence, we advise users of potato systems using CUPS to
upgrade to woody soon.

For the current stable distribution (woody), these problems have been fixed
in version 1.1.14-4.3.

For the old stable distribution (potato), these problems have been fixed
in version 1.0.4-12.1.

For the unstable distribution (sid), these problems have been fixed in
version 1.1.18-1.

We recommend that you upgrade your CUPS packages immediately.";
tag_summary = "The remote host is missing an update to cupsys
announced via advisory DSA 232-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20232-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302106");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2002-1366", "CVE-2002-1367", "CVE-2002-1368", "CVE-2002-1369", "CVE-2002-1371", "CVE-2002-1372", "CVE-2002-1383", "CVE-2002-1384");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 232-1 (cupsys)");



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
if ((res = isdpkgvuln(pkg:"cupsys", ver:"1.0.4-12.1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys-bsd", ver:"1.0.4-12.1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsys1", ver:"1.0.4-12.1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsys1-dev", ver:"1.0.4-12.1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys", ver:"1.1.14-4.3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys-bsd", ver:"1.1.14-4.3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys-client", ver:"1.1.14-4.3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys-pstoraster", ver:"1.1.14-4.3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsys2", ver:"1.1.14-4.3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsys2-dev", ver:"1.1.14-4.3", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
