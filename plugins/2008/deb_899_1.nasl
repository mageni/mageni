# OpenVAS Vulnerability Test
# $Id: deb_899_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 899-1
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
tag_solution = "For the stable distribution (sarge) this problem has been fixed in
version 1.0.0.007-2.dfsg-2sarge4.

For the unstable distribution (sid) this problem has been fixed in
version 1.0.0.009.dfsg-3-3.

We recommend that you upgrade your egroupware packages.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20899-1";
tag_summary = "The remote host is missing an update to egroupware
announced via advisory DSA 899-1.

Several vulnerabilities have been discovered in egroupware, a
web-based groupware suite.  The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2005-0870

Maksymilian Arciemowicz discoverd several cross site scripting
problems in phpsysinfo, which are also present in the imported
version in egroupware and of which not all were fixed in DSA 724.

CVE-2005-2600

Alexander Heidenreich discovered a cross-site scripting problem in
the tree view of FUD Forum Bulletin Board Software, which is also
present in egroupwre and allows remote attackers to read private
posts via a modified mid parameter.

CVE-2005-3347

Christopher Kunz discovered that local variables get overwritten
unconditionally in phpsyinfo, which are also present in
egroupware, and are trusted later, which could lead to the
inclusion of arbitrary files.

CVE-2005-3348

Christopher Kunz discovered that user-supplied input is used
unsanitised in phpsyinfo and imported in egroupware, causing a
HTTP Response splitting problem.

The old stable distribution (woody) does not contain egroupware packages.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.300380");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:03:37 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2005-0870", "CVE-2005-2600", "CVE-2005-3347", "CVE-2005-3348");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 899-1 (egroupware)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"egroupware-addressbook", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-bookmarks", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-calendar", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-comic", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-core", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-developer-tools", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-email", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-emailadmin", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-etemplate", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-felamimail", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-filemanager", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-forum", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-ftp", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-fudforum", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-headlines", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-infolog", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-jinn", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-ldap", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-manual", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-messenger", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-news-admin", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-phpbrain", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-phpldapadmin", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-phpsysinfo", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-polls", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-projects", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-registration", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-sitemgr", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-stocks", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-tts", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-wiki", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
