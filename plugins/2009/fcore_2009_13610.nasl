# OpenVAS Vulnerability Test
# $Id: fcore_2009_13610.nasl 6624 2017-07-10 06:11:55Z cfischer $
# Description: Auto-generated from advisory FEDORA-2009-13610 (viewvc)
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
tag_insight = "Update Information:

* security fix: add root listing support of per-root authz config
* security fix: query.py requires 'forbidden' authorizer (or none) in config
* fix URL-ification of truncated log messages (issue #3)
* fix regexp input validation (issue #426, #427, #440)
* add support for configurable tab-to-spaces conversion
* fix not-a-sequence error in diff view
* allow viewvc-install to work when templates-contrib is absent
* minor template improvements/corrections
* expose revision metadata in diff view (issue #431)
* markup file/directory item property URLs and email addresses (issue #434)
* make ViewVC cross copies in Subversion history by default
* fix bug that caused standalone.py failure under Python 1.5.2 (issue #442)
* fix support for per-vhost overrides of authorizer parameters (issue #411)
* fix root name identification in query.py interface

ChangeLog:

* Wed Dec 23 2009 Bojan Smojver  - 1.1.3-1
- bump up to 1.1.3
- drop patch for upstream issue #427";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update viewvc' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-13610";
tag_summary = "The remote host is missing an update to viewvc
announced via advisory FEDORA-2009-13610.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.306146");
 script_version("$Revision: 6624 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:11:55 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Fedora Core 12 FEDORA-2009-13610 (viewvc)");



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
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"viewvc", rpm:"viewvc~1.1.3~1.fc12", rls:"FC12")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"viewvc-httpd", rpm:"viewvc-httpd~1.1.3~1.fc12", rls:"FC12")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
