# OpenVAS Vulnerability Test
# $Id: RHSA_2009_0451.nasl 6683 2017-07-12 09:41:57Z cfischer $
# Description: Auto-generated from advisory RHSA-2009:0451 ()
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
advisory RHSA-2009:0451.

The kernel-rt packages contain the Linux kernel, the core of any Linux
operating system.

These updated packages fix the following security issues:

* a logic error was found in the do_setlk() function of the Linux kernel
Network File System (NFS) implementation. If a signal interrupted a lock
request, the local POSIX lock was incorrectly created. This could cause a
denial of service on the NFS server if a file descriptor was closed before
its corresponding lock request returned. (CVE-2008-4307, Important)

* a deficiency was found in the Linux kernel system call auditing
implementation on 64-bit systems. This could allow a local, unprivileged
user to circumvent a system call audit configuration, if that configuration
filtered based on the syscall number or arguments.
(CVE-2009-0834, Important)

* Chris Evans reported a deficiency in the Linux kernel secure-computing
implementation on 64-bit systems. This could allow a local, unprivileged
user to bypass intended access restrictions, if those access restriction
filters were based on the syscall number or arguments.
(CVE-2009-0835, Important)

* the exit_notify() function in the Linux kernel did not properly reset the
exit signal if a process executed a set user ID (setuid) application before
exiting. This could allow a local, unprivileged user to elevate their
privileges. (CVE-2009-1337, Important)

* Chris Evans reported a deficiency in the Linux kernel signals
implementation. The clone() system call permits the caller to indicate the
signal it wants to receive when its child exits. When clone() is called
with the CLONE_PARENT flag, it permits the caller to clone a new child that
shares the same parent as itself, enabling the indicated signal to be sent
to the caller's parent (instead of the caller), even if the caller's parent
has different real and effective user IDs. This could lead to a denial of
service of the parent. (CVE-2009-0028, Moderate)

* an off-by-two error was found in the set_selection() function of the
Linux kernel. This could allow a local, unprivileged user to cause a denial
of service when making a selection of characters in a UTF-8 console. Note:
physical console access is required to exploit this issue.
(CVE-2009-1046, Low)

These updated packages also fix the following bug:

* the __scsi_device_lookup_by_target() function was always returning the
first matching device, regardless of the state of the device. This meant
that any valid device listed after a deleted device would not be found. The
__scsi_device_lookup_by_target() function was modified so that deleted
devices are skipped, and valid devices are now found. (BZ#495976)

All Red Hat Enterprise MRG users should install this update, which resolves
these issues. For this update to take effect, the system must be rebooted.";

tag_solution = "Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.307573");
 script_version("$Revision: 6683 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-05-05 16:00:35 +0200 (Tue, 05 May 2009)");
 script_cve_id("CVE-2008-4307", "CVE-2009-0028", "CVE-2009-0834", "CVE-2009-0835", "CVE-2009-1046", "CVE-2009-1337");
 script_tag(name:"cvss_base", value:"4.7");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
 script_name("RedHat Security Advisory RHSA-2009:0451");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Red Hat Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2009-0451.html");
 script_xref(name : "URL" , value : "http://www.redhat.com/security/updates/classification/#important");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~2.6.24.7~111.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-debug", rpm:"kernel-rt-debug~2.6.24.7~111.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-debug-debuginfo", rpm:"kernel-rt-debug-debuginfo~2.6.24.7~111.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-debug-devel", rpm:"kernel-rt-debug-devel~2.6.24.7~111.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~2.6.24.7~111.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-debuginfo-common", rpm:"kernel-rt-debuginfo-common~2.6.24.7~111.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-devel", rpm:"kernel-rt-devel~2.6.24.7~111.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-trace", rpm:"kernel-rt-trace~2.6.24.7~111.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-trace-debuginfo", rpm:"kernel-rt-trace-debuginfo~2.6.24.7~111.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-trace-devel", rpm:"kernel-rt-trace-devel~2.6.24.7~111.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-vanilla", rpm:"kernel-rt-vanilla~2.6.24.7~111.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-vanilla-debuginfo", rpm:"kernel-rt-vanilla-debuginfo~2.6.24.7~111.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-vanilla-devel", rpm:"kernel-rt-vanilla-devel~2.6.24.7~111.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-doc", rpm:"kernel-rt-doc~2.6.24.7~111.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
