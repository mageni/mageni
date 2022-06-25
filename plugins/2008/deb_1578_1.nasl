# OpenVAS Vulnerability Test
# $Id: deb_1578_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1578-1 (php4)
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
tag_insight = "Several vulnerabilities have been discovered in PHP version 4, a
server-side, HTML-embedded scripting language. The Common Vulnerabilities
and Exposures project identifies the following problems:

CVE-2007-3799

The session_start function allows remote attackers to insert
arbitrary attributes into the session cookie via special characters
in a cookie that is obtained from various parameters.

CVE-2007-3806

A denial of service was possible through a malicious script abusing
the glob() function.

CVE-2007-3998

Certain maliciously constructed input to the wordwrap() function could
lead to a denial of service attack.

CVE-2007-4657

Large len values of the stspn() or strcspn() functions could allow an
attacker to trigger integer overflows to expose memory or cause denial
of service.

CVE-2008-2051

The escapeshellcmd API function could be attacked via incomplete
multibyte chars.


For the stable distribution (etch), these problems have been fixed in
version 6:4.4.4-8+etch6.

The php4 are no longer present the unstable distribution (sid).

We recommend that you upgrade your php4 package.";
tag_summary = "The remote host is missing an update to php4
announced via advisory DSA 1578-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201578-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303788");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-05-27 15:41:50 +0200 (Tue, 27 May 2008)");
 script_cve_id("CVE-2007-3799", "CVE-2007-3806", "CVE-2007-3998", "CVE-2007-4657", "CVE-2008-2051");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 1578-1 (php4)");



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
if ((res = isdpkgvuln(pkg:"php4", ver:"4.4.4-8+etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4-pear", ver:"4.4.4-8+etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4-xslt", ver:"4.4.4-8+etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-mod-php4", ver:"4.4.4-8+etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4-cgi", ver:"4.4.4-8+etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4-odbc", ver:"4.4.4-8+etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4-pspell", ver:"4.4.4-8+etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4-mysql", ver:"4.4.4-8+etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4-gd", ver:"4.4.4-8+etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4-domxml", ver:"4.4.4-8+etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4-curl", ver:"4.4.4-8+etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4-dev", ver:"4.4.4-8+etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4-sybase", ver:"4.4.4-8+etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4-mcal", ver:"4.4.4-8+etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache-mod-php4", ver:"4.4.4-8+etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4-imap", ver:"4.4.4-8+etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4-mcrypt", ver:"4.4.4-8+etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4-recode", ver:"4.4.4-8+etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4-pgsql", ver:"4.4.4-8+etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4-common", ver:"4.4.4-8+etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4-cli", ver:"4.4.4-8+etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4-mhash", ver:"4.4.4-8+etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4-ldap", ver:"4.4.4-8+etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4-snmp", ver:"4.4.4-8+etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"php4-interbase", ver:"4.4.4-8+etch6", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
