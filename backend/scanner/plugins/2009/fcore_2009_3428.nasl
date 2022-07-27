# OpenVAS Vulnerability Test
# $Id: fcore_2009_3428.nasl 6624 2017-07-10 06:11:55Z cfischer $
# Description: Auto-generated from advisory FEDORA-2009-3428 (xine-lib)
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

Maintenance release. Fixes two security problems (CVE-2009-0385, CVE-2009-1274)
and a few miscellaneous bugs.    See the upstream changelog for details:
http://sourceforge.net/project/shownotes.php?group_id=9655&release_id=673233

ChangeLog:

* Fri Apr  3 2009 Rex Dieter  - 1.1.16.3-1
- xine-lib-1.1.16.3, plugin-abi 1.26
* Thu Mar 26 2009 Rex Dieter  - 1.1.16.2-6
- add-mime-for-mod.patch
* Tue Mar 10 2009 Kevin Kofler  - 1.1.16.2-5
- rebuild for new ImageMagick
* Thu Feb 26 2009 Fedora Release Engineering  - 1.1.16.2-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild
* Fri Feb 20 2009 Rex Dieter  - 1.1.16.2-3
- xine-lib-devel muiltilib conflict (#477226)";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update xine-lib' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3428";
tag_summary = "The remote host is missing an update to xine-lib
announced via advisory FEDORA-2009-3428.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.307002");
 script_version("$Revision: 6624 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:11:55 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-04-15 22:11:00 +0200 (Wed, 15 Apr 2009)");
 script_cve_id("CVE-2009-0385", "CVE-2009-1274", "CVE-2008-3231");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Fedora Core 9 FEDORA-2009-3428 (xine-lib)");



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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=495031");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"xine-lib", rpm:"xine-lib~1.1.16.3~1.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-lib-devel", rpm:"xine-lib-devel~1.1.16.3~1.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-lib-extras", rpm:"xine-lib-extras~1.1.16.3~1.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-lib-pulseaudio", rpm:"xine-lib-pulseaudio~1.1.16.3~1.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xine-lib-debuginfo", rpm:"xine-lib-debuginfo~1.1.16.3~1.fc9", rls:"FC9")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
