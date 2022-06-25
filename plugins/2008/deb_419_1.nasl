# OpenVAS Vulnerability Test
# $Id: deb_419_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 419-1
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
tag_insight = "The authors of phpgroupware, a web based groupware system written in
PHP, discovered several vulnerabilities.  The Common Vulnerabilities
and Exposures project identifies the following problems:

CVE-2004-0016

In the calendar module, save extension was not enforced for
holiday files.  As a result, server-side php scripts may be placed
in directories that then could be accessed remotely and cause the
webserver to execute those.  This was resolved by enforcing the
extension .txt for holiday files.

CVE-2004-0017

Some SQL injection problems (non-escaping of values used in SQL
strings) the calendar and infolog modules.

Additionally, the Debian maintainer adjusted the permissions on world
writable directories that were accidentally created by former postinst
during the installation.

For the stable distribution (woody) this problem has been fixed in
version 0.9.14-0.RC3.2.woody3.

For the unstable distribution (sid) this problem has been fixed in
version 0.9.14.007-4.

We recommend that you upgrade your phpgroupware, phpgroupware-calendar";
tag_summary = "The remote host is missing an update to phpgroupware
announced via advisory DSA 419-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20419-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.303313");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2004-0016", "CVE-2004-0017");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 419-1 (phpgroupware)");



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
if ((res = isdpkgvuln(pkg:"phpgroupware-addressbook", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-admin", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-api-doc", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-api", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-bookkeeping", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-bookmarks", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-brewer", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-calendar", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-chat", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-chora", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-comic", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-core-doc", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-core", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-developer-tools", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-dj", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-eldaptir", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-email", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-filemanager", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-forum", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-ftp", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-headlines", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-hr", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-img", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-infolog", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-inv", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-manual", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-messenger", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-napster", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-news-admin", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-nntp", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-notes", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-phonelog", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-phpsysinfo", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-phpwebhosting", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-polls", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-preferences", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-projects", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-registration", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-setup", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-skel", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-soap", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-stocks", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-todo", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-tts", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-wap", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-weather", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-xmlrpc", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
