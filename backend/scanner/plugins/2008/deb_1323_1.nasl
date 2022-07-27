# OpenVAS Vulnerability Test
# $Id: deb_1323_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1323-1
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
tag_insight = "Several remote vulnerabilities have been discovered in the MIT reference
implementation of the Kerberos network authentication protocol suite,
which may lead to the execution of arbitrary code. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-2442

Wei Wang discovered that the free of an uninitialised pointer in the
Kerberos RPC library may lead to the execution of arbitrary code.

CVE-2007-2443

Wei Wang discovered that insufficient input sanitising in the
Kerberos RPC library may lead to the execution of arbitrary code.

CVE-2007-2798

It was discovered that a buffer overflow in the  Kerberos
administration daemon may lead to the execution of arbitrary code.

For the old stable distribution (sarge) these problems have been fixed in
version 1.3.6-2sarge5. Packages for hppa, mips and powerpc are not yet
available. They will be provided later.

For the stable distribution (etch) these problems have been fixed in
version 1.4.4-7etch2. Packages for hppa and mips are not yet available.
They will be provided later.

For the unstable distribution (sid) these problems have been fixed in
version 1.6.dfsg.1-5.

We recommend that you upgrade your Kerberos packages.";
tag_summary = "The remote host is missing an update to krb5
announced via advisory DSA 1323-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201323-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303862");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:19:52 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2007-2442", "CVE-2007-2443", "CVE-2007-2798");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1323-1 (krb5)");



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
if ((res = isdpkgvuln(pkg:"krb5-doc", ver:"1.3.6-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.3.6-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-clients", ver:"1.3.6-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-ftpd", ver:"1.3.6-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.3.6-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-rsh-server", ver:"1.3.6-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-telnetd", ver:"1.3.6-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-user", ver:"1.3.6-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkadm55", ver:"1.3.6-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.3.6-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkrb53", ver:"1.3.6-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-doc", ver:"1.4.4-7etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.4.4-7etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-clients", ver:"1.4.4-7etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-ftpd", ver:"1.4.4-7etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.4.4-7etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-rsh-server", ver:"1.4.4-7etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-telnetd", ver:"1.4.4-7etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-user", ver:"1.4.4-7etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkadm55", ver:"1.4.4-7etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkrb5-dbg", ver:"1.4.4-7etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.4.4-7etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkrb53", ver:"1.4.4-7etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
