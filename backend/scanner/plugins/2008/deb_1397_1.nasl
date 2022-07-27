# OpenVAS Vulnerability Test
# $Id: deb_1397_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1397-1
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
tag_insight = "An integer overflow in the BigInteger data type implementation has been
discovred in the free .NET runtime Mono.

The oldstable distribution (sarge) doesn't contain mono.

For the stable distribution (etch) this problem has been fixed in
version 1.2.2.1-1etch1. A powerpc build will be provided later.

The unstable distribution (sid) will be fixed soon.

We recommend that you upgrade your mono packages.";
tag_summary = "The remote host is missing an update to mono
announced via advisory DSA 1397-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201397-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.302436");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:19:52 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2007-5197");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1397-1 (mono)");



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
if ((res = isdpkgvuln(pkg:"libmono-accessibility1.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-accessibility2.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-bytefx0.7.6.1-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-bytefx0.7.6.2-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-c5-1.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-cairo1.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-cairo2.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-corlib1.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-corlib2.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-cscompmgd7.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-cscompmgd8.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-data-tds1.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-data-tds2.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-firebirdsql1.7-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-ldap1.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-ldap2.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-microsoft-build2.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-microsoft7.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-microsoft8.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-npgsql1.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-npgsql2.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-oracle1.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-oracle2.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-peapi1.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-peapi2.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-relaxng1.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-relaxng2.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-security1.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-security2.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-sharpzip0.6-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-sharpzip0.84-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-sharpzip2.6-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-sharpzip2.84-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-sqlite1.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-sqlite2.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-data1.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-data2.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-ldap1.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-ldap2.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-messaging1.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-messaging2.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-runtime1.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-runtime2.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-web1.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system-web2.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system1.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-system2.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-winforms1.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-winforms2.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono1.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono2.0-cil", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-gac", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-gmcs", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-mcs", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-mjs", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono-dev", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmono0", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-common", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-devel", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-jay", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-jit", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-runtime", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mono-utils", ver:"1.2.2.1-1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
