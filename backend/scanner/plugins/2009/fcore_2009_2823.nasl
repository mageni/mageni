# OpenVAS Vulnerability Test
# $Id: fcore_2009_2823.nasl 6624 2017-07-10 06:11:55Z cfischer $
# Description: Auto-generated from advisory FEDORA-2009-2823 (php-ZendFramework)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Extending the art & spirit of PHP, Zend Framework is based on simplicity,
object-oriented best practices, corporate friendly licensing, and a rigorously
tested agile codebase. Zend Framework is focused on building more secure,
reliable, and modern Web 2.0 applications & web services, and consuming widely
available APIs from leading vendors like Google, Amazon, Yahoo!, Flickr, as
well as API providers and catalogers like StrikeIron and ProgrammableWeb.

ChangeLog:

* Tue Mar 17 2009 Alexander Kahl  - 1.7.7-2
- bump (cannot remove spurious -1 tag)
* Tue Mar 17 2009 Alexander Kahl  - 1.7.7-1
- update to 1.7.7
- PHPUnit dep now >= 3.3.0
- moved Ldap bindings to extra packages (php-ldap dep)
- excluded db adapters with unresolvable deps
- moved mysqli db adapter files to correct package
- support both old and new font deps using conditional";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update php-ZendFramework' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-2823";
tag_summary = "The remote host is missing an update to php-ZendFramework
announced via advisory FEDORA-2009-2823.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311625");
 script_version("$Revision: 6624 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:11:55 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-06-23 15:49:15 +0200 (Tue, 23 Jun 2009)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Fedora Core 10 FEDORA-2009-2823 (php-ZendFramework)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Fedora Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=487696");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"php-ZendFramework", rpm:"php-ZendFramework~1.7.7~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Auth", rpm:"php-ZendFramework-Auth~Adapter~Ldap", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Cache", rpm:"php-ZendFramework-Cache~Backend~Apc", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Cache", rpm:"php-ZendFramework-Cache~Backend~Memcached", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Captcha", rpm:"php-ZendFramework-Captcha~1.7.7~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Db", rpm:"php-ZendFramework-Db~Adapter~Mysqli", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Dojo", rpm:"php-ZendFramework-Dojo~1.7.7~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Feed", rpm:"php-ZendFramework-Feed~1.7.7~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Gdata", rpm:"php-ZendFramework-Gdata~1.7.7~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Ldap", rpm:"php-ZendFramework-Ldap~1.7.7~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Pdf", rpm:"php-ZendFramework-Pdf~1.7.7~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Search", rpm:"php-ZendFramework-Search~Lucene~1.7.7", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-Services", rpm:"php-ZendFramework-Services~1.7.7~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-demos", rpm:"php-ZendFramework-demos~1.7.7~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-extras", rpm:"php-ZendFramework-extras~1.7.7~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-ZendFramework-tests", rpm:"php-ZendFramework-tests~1.7.7~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
