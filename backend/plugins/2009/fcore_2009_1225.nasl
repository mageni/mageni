# OpenVAS Vulnerability Test
# $Id: fcore_2009_1225.nasl 6624 2017-07-10 06:11:55Z cfischer $
# Description: Auto-generated from advisory FEDORA-2009-1225 (gpsdrive)
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
tag_insight = "Gpsdrive is a map-based navigation system.
It displays your position on a zoomable map
provided from a NMEA-capable GPS receiver. The maps are autoselected
for the best resolution, depending of your position, and the displayed
image can be zoomed. Maps can be downloaded from the Internet with one
mouse click. The program provides information about speed, direction,
bearing, arrival time, actual position, and target position.
Speech output is also available. MySQL is supported.

Update Information:

This update removes several helper scripts: geo-code, geo-nearest, and
gpssmswatch, which have been removed upstream due to security issues. This
update also has a fix for an issue with the splash screen.
ChangeLog:

* Mon Feb  2 2009 Kevin Fenzi  - 2.09-7
- fix for CVE-2008-4959 - bug 470241
- fix for CVE-2008-5380 - bug 475478
- fix for CVE-2008-5703 - bug 481702";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update gpsdrive' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-1225";
tag_summary = "The remote host is missing an update to gpsdrive
announced via advisory FEDORA-2009-1225.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.309111");
 script_version("$Revision: 6624 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:11:55 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-02-10 15:52:40 +0100 (Tue, 10 Feb 2009)");
 script_cve_id("CVE-2008-4959", "CVE-2008-5380", "CVE-2008-5703");
 script_tag(name:"cvss_base", value:"6.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Fedora Core 10 FEDORA-2009-1225 (gpsdrive)");



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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=470241");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=475478");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=481702");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"gpsdrive", rpm:"gpsdrive~2.09~7.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gpsdrive-debuginfo", rpm:"gpsdrive-debuginfo~2.09~7.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
