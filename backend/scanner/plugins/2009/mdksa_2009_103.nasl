# OpenVAS Vulnerability Test
# $Id: mdksa_2009_103.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:103 (udev)
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
tag_insight = "Security vulnerabilities have been identified and fixed in udev.

udev before 1.4.1 does not verify whether a NETLINK message originates
from kernel space, which allows local users to gain privileges by
sending a NETLINK message from user space (CVE-2009-1185).

Buffer overflow in the util_path_encode function in
udev/lib/libudev-util.c in udev before 1.4.1 allows local users to
cause a denial of service (service outage) via vectors that trigger
a call with crafted arguments (CVE-2009-1186).

The updated packages have been patched to prevent this.

Affected: 2008.1, 2009.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:103";
tag_summary = "The remote host is missing an update to udev
announced via advisory MDVSA-2009:103.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311615");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-05-05 16:00:35 +0200 (Tue, 05 May 2009)");
 script_cve_id("CVE-2009-1185", "CVE-2009-1186");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Mandrake Security Advisory MDVSA-2009:103 (udev)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Mandrake Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms");
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
if ((res = isrpmvuln(pkg:"libvolume_id0", rpm:"libvolume_id0~118~6.3mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libvolume_id0-devel", rpm:"libvolume_id0-devel~118~6.3mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"udev", rpm:"udev~118~6.3mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"udev-doc", rpm:"udev-doc~118~6.3mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"udev-tools", rpm:"udev-tools~118~6.3mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64volume_id0", rpm:"lib64volume_id0~118~6.3mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64volume_id0-devel", rpm:"lib64volume_id0-devel~118~6.3mnb1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libudev0", rpm:"libudev0~128~2.2mnb2", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libudev0-devel", rpm:"libudev0-devel~128~2.2mnb2", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libvolume_id1", rpm:"libvolume_id1~128~2.2mnb2", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libvolume_id1-devel", rpm:"libvolume_id1-devel~128~2.2mnb2", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"udev", rpm:"udev~128~2.2mnb2", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"udev-doc", rpm:"udev-doc~128~2.2mnb2", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64udev0", rpm:"lib64udev0~128~2.2mnb2", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64udev0-devel", rpm:"lib64udev0-devel~128~2.2mnb2", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64volume_id1", rpm:"lib64volume_id1~128~2.2mnb2", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64volume_id1-devel", rpm:"lib64volume_id1-devel~128~2.2mnb2", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
