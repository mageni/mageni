# OpenVAS Vulnerability Test
# $Id: fcore_2009_8507.nasl 6624 2017-07-10 06:11:55Z cfischer $
# Description: Auto-generated from advisory FEDORA-2009-8507 (viewvc)
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

CHANGES in 1.1.2:
- security fix: validate the 'view' parameter to avoid XSS attack
- security fix: avoid printing illegal parameter names and values
- add optional support for character encoding detection (issue #400)
- fix username case handling in svnauthz module (issue #419)
- fix cvsdbadmin/svnadmin rebuild error on missing repos (issue #420)
- don't drop leading blank lines from colorized file contents (issue #422)
- add file.ezt template logic for optionally hiding binary file contents

Also includes:    Install and populate mimetypes.conf. This should
hopefully help when colouring syntax using pygments.
Install and populate mimetypes.conf.

ChangeLog:

* Wed Aug 12 2009 Bojan Smojver  - 1.1.2-2
- fix replacement of varius config variables
* Wed Aug 12 2009 Bojan Smojver  - 1.1.2-1
- bump up to 1.1.2
- security fix: validate the 'view' parameter to avoid XSS attack
- security fix: avoid printing illegal parameter names and values
* Tue Aug 11 2009 Bojan Smojver  - 1.1.1-2
- install mimetypes.conf
- populate mimetypes.conf with what pygments understands";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update viewvc' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8507";
tag_summary = "The remote host is missing an update to viewvc
announced via advisory FEDORA-2009-8507.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.310836");
 script_cve_id("CVE-2009-3618","CVE-2009-3619");
 script_version("$Revision: 6624 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:11:55 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Fedora Core 11 FEDORA-2009-8507 (viewvc)");



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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=516958");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=514909");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=514773");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"viewvc", rpm:"viewvc~1.1.2~2.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"viewvc-httpd", rpm:"viewvc-httpd~1.1.2~2.fc11", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
