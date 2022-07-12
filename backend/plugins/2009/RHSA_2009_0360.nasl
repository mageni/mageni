# OpenVAS Vulnerability Test
# $Id: RHSA_2009_0360.nasl 6683 2017-07-12 09:41:57Z cfischer $
# Description: Auto-generated from advisory RHSA-2009:0360 ()
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
tag_summary = "The remote host is missing updates announced in
advisory RHSA-2009:0360.

The kernel-rt packages contain the Linux kernel, the core of any Linux
operating system.

These updated packages address the following security issues:

* a memory leak exists in keyctl handling. A local, unprivileged user could
use this flaw to deplete kernel memory, eventually leading to a denial of
service. (CVE-2009-0031, Important)

* an off-by-one underflow flaw was found in the eCryptfs subsystem. This
could potentially cause a denial of service when the readlink() function
returned an error. (CVE-2009-0269, Moderate)

* a deficiency was found in the Remote BIOS Update (RBU) driver for Dell
systems. This could allow a local, unprivileged user to cause a denial of
service by reading zero bytes from the image_type or packet_size files in
/sys/devices/platform/dell_rbu/. (CVE-2009-0322, Moderate)

* an inverted logic flaw was found in the SysKonnect FDDI PCI adapter
driver, allowing driver statistics to be reset only when the CAP_NET_ADMIN
capability was absent (local, unprivileged users could reset driver
statistics). (CVE-2009-0675, Moderate)

* the sock_getsockopt() function in the Linux kernel did not properly
initialize a data structure that can be directly returned to user-space
when the getsockopt() function is called with SO_BSDCOMPAT optname set.
This flaw could possibly lead to memory disclosure.
(CVE-2009-0676, Moderate)

For other issues addressed in this update, please visit the referenced
advisories.

All Red Hat Enterprise MRG users should install this update which addresses
these vulnerabilities and fixes these bugs. For this update to take effect,
the system must be rebooted.";

tag_solution = "Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305936");
 script_version("$Revision: 6683 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-03-31 19:20:21 +0200 (Tue, 31 Mar 2009)");
 script_cve_id("CVE-2009-0031", "CVE-2009-0269", "CVE-2009-0322", "CVE-2009-0675", "CVE-2009-0676");
 script_tag(name:"cvss_base", value:"4.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
 script_name("RedHat Security Advisory RHSA-2009:0360");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Red Hat Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2009-0360.html");
 script_xref(name : "URL" , value : "http://www.redhat.com/security/updates/classification/#important");
 script_xref(name : "URL" , value : "http://www.redhat.com/docs/en-US/Red_Hat_Enterprise_MRG/");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~2.6.24.7~108.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-debug", rpm:"kernel-rt-debug~2.6.24.7~108.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-debug-debuginfo", rpm:"kernel-rt-debug-debuginfo~2.6.24.7~108.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-debug-devel", rpm:"kernel-rt-debug-devel~2.6.24.7~108.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~2.6.24.7~108.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-debuginfo-common", rpm:"kernel-rt-debuginfo-common~2.6.24.7~108.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-devel", rpm:"kernel-rt-devel~2.6.24.7~108.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-trace", rpm:"kernel-rt-trace~2.6.24.7~108.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-trace-debuginfo", rpm:"kernel-rt-trace-debuginfo~2.6.24.7~108.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-trace-devel", rpm:"kernel-rt-trace-devel~2.6.24.7~108.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-vanilla", rpm:"kernel-rt-vanilla~2.6.24.7~108.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-vanilla-debuginfo", rpm:"kernel-rt-vanilla-debuginfo~2.6.24.7~108.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-vanilla-devel", rpm:"kernel-rt-vanilla-devel~2.6.24.7~108.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-doc", rpm:"kernel-rt-doc~2.6.24.7~108.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
