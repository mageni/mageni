# OpenVAS Vulnerability Test
# $Id: deb_185_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 185-1
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
tag_insight = "A stack buffer overflow in the kadm_ser_wrap_in function in the
Kerberos v4 administration server was discovered, which is provided by
Heimdal as well.  A working exploit for this kadmind bug is already
circulating, hence it is considered serious.  The roken library also
contains a vulnerability which could lead to another root exploit.

These problems have been fixed in version 0.4e-7.woody.5 for the
current stable distribution (woody), in version 0.2l-7.6 for the old
stable distribution (potato) and in version 0.4e-22 for the unstable
distribution (sid).

We recommend that you upgrade your heimdal packages immediately.";
tag_summary = "The remote host is missing an update to heimdal
announced via advisory DSA 185-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20185-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303179");
 script_cve_id("CVE-2002-1235");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 185-1 (heimdal)");



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
if ((res = isdpkgvuln(pkg:"heimdal-docs", ver:"0.2l-7.6", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"heimdal-clients", ver:"0.2l-7.6", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"heimdal-clients-x", ver:"0.2l-7.6", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"heimdal-dev", ver:"0.2l-7.6", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"heimdal-kdc", ver:"0.2l-7.6", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"heimdal-lib", ver:"0.2l-7.6", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"heimdal-servers", ver:"0.2l-7.6", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"heimdal-servers-x", ver:"0.2l-7.6", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"heimdal-docs", ver:"0.4e-7.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"heimdal-lib", ver:"0.4e-7.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"heimdal-clients", ver:"0.4e-7.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"heimdal-clients-x", ver:"0.4e-7.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"heimdal-dev", ver:"0.4e-7.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"heimdal-kdc", ver:"0.4e-7.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"heimdal-servers", ver:"0.4e-7.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"heimdal-servers-x", ver:"0.4e-7.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libasn1-5-heimdal", ver:"0.4e-7.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcomerr1-heimdal", ver:"0.4e-7.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgssapi1-heimdal", ver:"0.4e-7.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libhdb7-heimdal", ver:"0.4e-7.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkadm5clnt4-heimdal", ver:"0.4e-7.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkadm5srv7-heimdal", ver:"0.4e-7.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkafs0-heimdal", ver:"0.4e-7.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkrb5-17-heimdal", ver:"0.4e-7.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libotp0-heimdal", ver:"0.4e-7.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libroken9-heimdal", ver:"0.4e-7.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsl0-heimdal", ver:"0.4e-7.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libss0-heimdal", ver:"0.4e-7.woody.5", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
