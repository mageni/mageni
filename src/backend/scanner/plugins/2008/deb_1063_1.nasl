# OpenVAS Vulnerability Test
# $Id: deb_1063_1.nasl 6616 2017-07-07 12:10:49Z cfischer $
# Description: Auto-generated from advisory DSA 1063-1
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
version 0.9.16.005-3.sarge5.

For the unstable distribution (sid) this problem has been fixed in
version 0.9.16.009-1.

We recommend that you upgrade your XXXXXXXXXXXXXX package.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201063-1";
tag_summary = "The remote host is missing an update to phpgroupware
announced via advisory DSA 1063-1.

It was discovered that the Avatar upload feature of FUD Forum, a component
of the web based groupware system phpgroupware, does not sufficiently
validate uploaded files, which might lead to the execution of injected web
script code.

For the old stable distribution (woody) this problem has been fixed in
version 0.9.14-0.RC3.2.woody6.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304066");
 script_version("$Revision: 6616 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 14:10:49 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:09:45 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2005-2781");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 1063-1 (phpgroupware)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"phpgroupware-addressbook", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-admin", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-api-doc", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-api", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-bookkeeping", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-bookmarks", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-brewer", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-calendar", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-chat", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-chora", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-comic", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-core-doc", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-core", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-developer-tools", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-dj", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-eldaptir", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-email", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-filemanager", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-forum", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-ftp", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-headlines", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-hr", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-img", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-infolog", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-inv", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-manual", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-messenger", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-napster", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-news-admin", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-nntp", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-notes", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-phonelog", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-phpsysinfo", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-phpwebhosting", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-polls", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-preferences", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-projects", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-registration", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-setup", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-skel", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-soap", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-stocks", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-todo", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-tts", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-wap", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-weather", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-xmlrpc", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware", ver:"0.9.14-0.RC3.2.woody6", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-addressbook", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-admin", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-bookmarks", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-calendar", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-chat", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-comic", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-core", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-developer-tools", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-dj", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-eldaptir", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-email", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-etemplate", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-felamimail", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-filemanager", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-folders", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-forum", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-ftp", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-fudforum", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-headlines", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-hr", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-img", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-infolog", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-manual", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-messenger", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-news-admin", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-nntp", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-notes", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-phonelog", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-phpbrain", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-phpgwapi", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-phpsysinfo", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-polls", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-preferences", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-projects", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-qmailldap", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-registration", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-setup", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-sitemgr", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-skel", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-soap", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-stocks", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-todo", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-tts", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-wiki", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware-xmlrpc", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpgroupware", ver:"0.9.16.005-3.sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
