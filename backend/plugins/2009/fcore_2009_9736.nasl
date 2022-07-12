# OpenVAS Vulnerability Test
# $Id: fcore_2009_9736.nasl 6624 2017-07-10 06:11:55Z cfischer $
# Description: Auto-generated from advisory FEDORA-2009-9736 (drupal-date)
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

* Advisory ID: DRUPAL-SA-CONTRIB-2009-057 ( http://drupal.org/node/579144 )
* Project: Date (third-party module)
* Version: 5.x, 6.x
* Date: 2009-September-16
* Security risk: Moderately critical
* Exploitable from: Remote
* Vulnerability: Cross Site Scripting


ChangeLog:

* Wed Sep 16 2009 Jon Ciesla  - 6.x.2.4-0
- Update to new version.
- Fix for DRUPAL-SA-CONTRIB-2009-057.";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update drupal-date' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-9736";
tag_summary = "The remote host is missing an update to drupal-date
announced via advisory FEDORA-2009-9736.";



if(description)
{
script_xref(name : "URL" , value : "http://en.wikipedia.org/wiki/Cross-site_scripting");
script_xref(name : "URL" , value : "http://drupal.org/node/579000");
script_xref(name : "URL" , value : "http://drupal.org/node/578998");
script_xref(name : "URL" , value : "http://drupal.org/project/date");
script_xref(name : "URL" , value : "http://drupal.org/user/45874");
 script_oid("1.3.6.1.4.1.25623.1.0.310382");
 script_version("$Revision: 6624 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:11:55 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-09-21 23:13:00 +0200 (Mon, 21 Sep 2009)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("Fedora Core 11 FEDORA-2009-9736 (drupal-date)");



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
if ((res = isrpmvuln(pkg:"drupal-date", rpm:"drupal-date~6.x.2.4~0.fc11", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
