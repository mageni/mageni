# OpenVAS Vulnerability Test
# $Id: deb_1978_1.nasl 8457 2018-01-18 07:58:32Z teissa $
# Description: Auto-generated from advisory DSA 1978-1 (phpgroupware)
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
tag_insight = "Several remote vulnerabilities have been discovered in phpgroupware, a
Web based groupware system written in PHP. The Common Vulnerabilities
and Exposures project identifies the following problems:

CVE-2009-4414

An SQL injection vulnerability was found in the authentication
module.

CVE-2009-4415

Multiple directory traversal vulnerabilities were found in the
addressbook module.

CVE-2009-4416

The authentication module is affected by cross-site scripting.


For the stable distribution (lenny) these problems have been fixed in
version 0.9.16.012+dfsg-8+lenny1.

For the unstable distribution (sid) these problems have been fixed in
version 0.9.16.012+dfsg-9.

We recommend that you upgrade your phpgroupware packages.";
tag_summary = "The remote host is missing an update to phpgroupware
announced via advisory DSA 1978-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201978-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.313034");
 script_version("$Revision: 8457 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-02-01 18:25:19 +0100 (Mon, 01 Feb 2010)");
 script_cve_id("CVE-2009-4414", "CVE-2009-4415", "CVE-2009-4416");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1978-1 (phpgroupware)");



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
if ((res = isdpkgvuln(pkg:"phpgroupware-0.9.16-email", ver:"0.9.16.012+dfsg-8+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-0.9.16-core-base", ver:"0.9.16.012+dfsg-8+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-0.9.16-calendar", ver:"0.9.16.012+dfsg-8+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-0.9.16-addressbook", ver:"0.9.16.012+dfsg-8+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware", ver:"0.9.16.012+dfsg-8+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-0.9.16-news-admin", ver:"0.9.16.012+dfsg-8+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-0.9.16-manual", ver:"0.9.16.012+dfsg-8+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-0.9.16-filemanager", ver:"0.9.16.012+dfsg-8+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-0.9.16-phpgwapi", ver:"0.9.16.012+dfsg-8+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-0.9.16-preferences", ver:"0.9.16.012+dfsg-8+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-0.9.16", ver:"0.9.16.012+dfsg-8+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-0.9.16-core", ver:"0.9.16.012+dfsg-8+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-0.9.16-admin", ver:"0.9.16.012+dfsg-8+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-0.9.16-notes", ver:"0.9.16.012+dfsg-8+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-0.9.16-doc", ver:"0.9.16.012+dfsg-8+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-0.9.16-phpgwapi-doc", ver:"0.9.16.012+dfsg-8+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-0.9.16-setup", ver:"0.9.16.012+dfsg-8+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-0.9.16-todo", ver:"0.9.16.012+dfsg-8+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
