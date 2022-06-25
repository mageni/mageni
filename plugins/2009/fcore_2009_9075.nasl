# OpenVAS Vulnerability Test
# $Id: fcore_2009_9075.nasl 6624 2017-07-10 06:11:55Z cfischer $
# Description: Auto-generated from advisory FEDORA-2009-9075 (dhcp)
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

Do not require policycoreutils when installing dhcp or dhclient packages.  If
you have the package installed, the /sbin/restorecon program will be used by
dhclient-script and the dhcpd init script.    This update to the dhcp package
includes fixes for CVE-2009-0692 and CVE-2009-1892.
Note: CVE-2009-0692 had no security consequences on Fedora, thanks to the
use of FORTIFY_SOURCE

ChangeLog:

* Wed Aug 26 2009 David Cantrell  - 12:4.1.0p1-4
- Do not require policycoreutils for dhclient subpackage, fix restorecon
calls in postinstall scriptlets (#519479)
* Wed Aug 26 2009 David Cantrell  - 12:4.1.0p1-3
- Do not require policycoreutils for post scriptlet (#519479)
* Thu Aug  6 2009 David Cantrell  - 12:4.1.0p1-2
- Add /usr/lib[64]/pm-utils/sleep.d/56dhclient to handle suspend and
resume with active dhclient leases (#479639)
* Wed Aug  5 2009 David Cantrell  - 12:4.1.0p1-1
- Upgrade to dhcp-4.1.0p1, which is the official upstream release to fix
CVE-2009-0692
* Wed Aug  5 2009 David Cantrell  - 12:4.1.0-25
- Fix for CVE-2009-0692
- Fix for CVE-2009-1892 (#511834)
- Disable patch for #514828 since that fix is still in updates-testing
* Tue Aug  4 2009 David Cantrell  - 12:4.1.0-24
- Correct lease file format written by dhclient (#514828)";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update dhcp' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-9075";
tag_summary = "The remote host is missing an update to dhcp
announced via advisory FEDORA-2009-9075.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304974");
 script_version("$Revision: 6624 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:11:55 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-11-17 21:42:12 +0100 (Tue, 17 Nov 2009)");
 script_cve_id("CVE-2009-0692", "CVE-2009-1892");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Fedora Core 11 FEDORA-2009-9075 (dhcp)");



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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=519479");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=511834");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"dhclient", rpm:"dhclient~4.1.0p1~4.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp", rpm:"dhcp~4.1.0p1~4.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-devel", rpm:"dhcp-devel~4.1.0p1~4.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"dhcp-debuginfo", rpm:"dhcp-debuginfo~4.1.0p1~4.fc11", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
