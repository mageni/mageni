# OpenVAS Vulnerability Test
# $Id: fcore_2009_3711.nasl 6624 2017-07-10 06:11:55Z cfischer $
# Description: Auto-generated from advisory FEDORA-2009-3711 (udev)
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
tag_insight = "The udev package contains an implementation of devfs in
userspace using sysfs and netlink.

Update Information:

udev provides a user-space API and implements a dynamic device directory,
providing only the devices present on the system. udev replaces devfs in order
to provide greater hot plug functionality. Netlink is a datagram oriented
service, used to transfer information between kernel modules and user-space
processes.

It was discovered that udev did not properly check the origin of
Netlink messages. A local attacker could use this flaw to gain root privileges
via a crafted Netlink message sent to udev, causing it to create a world-
writable block device file for an existing system block device (for example, the
root file system). (CVE-2009-1185)

An integer overflow flaw, potentially
leading to heap-based buffer overflow was found in one of the utilities
providing functionality of the udev device information interface. An attacker
could use this flaw to cause a denial of service, or possibly, to execute
arbitrary code by providing a specially-crafted arguments as input to this
utility. (CVE-2009-1186)

Thanks to Sebastian Krahmer of the SUSE Security Team for responsibly
reporting this flaw.  Users of udev are advised to upgrade to these
updated packages, which contain a backported patch to correct this issue.
After installing the update, the udevd daemon will be restarted automatically.

ChangeLog:

* Thu Apr 16 2009 Harald Hoyer  127-5
- fix for CVE-2009-1186
* Wed Apr 15 2009 Harald Hoyer  127-4
- fix for CVE-2009-1185";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update udev' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3711";
tag_summary = "The remote host is missing an update to udev
announced via advisory FEDORA-2009-3711.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.307050");
 script_version("$Revision: 6624 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:11:55 +0200 (Mon, 10 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-04-20 23:45:17 +0200 (Mon, 20 Apr 2009)");
 script_cve_id("CVE-2009-1185", "CVE-2009-1186");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Fedora Core 10 FEDORA-2009-3711 (udev)");



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
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=495051");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=495052");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libudev-devel", rpm:"libudev-devel~127~5.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libudev0", rpm:"libudev0~127~5.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libvolume_id", rpm:"libvolume_id~127~5.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libvolume_id-devel", rpm:"libvolume_id-devel~127~5.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"udev", rpm:"udev~127~5.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"udev-static", rpm:"udev-static~127~5.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"udev-debuginfo", rpm:"udev-debuginfo~127~5.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
