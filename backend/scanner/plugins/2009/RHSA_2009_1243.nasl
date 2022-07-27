# OpenVAS Vulnerability Test
# $Id: RHSA_2009_1243.nasl 6683 2017-07-12 09:41:57Z cfischer $
# Description: Auto-generated from advisory RHSA-2009:1243 ()
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
tag_solution = "Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date

http://rhn.redhat.com/errata/RHSA-2009-1243.html
http://www.redhat.com/security/updates/classification/#important
http://www.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/5.4/html/Release_Notes/
http://www.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/5.4/html/Technical_Notes/kernel.html";

tag_summary = "The remote host is missing updates announced in
advisory RHSA-2009:1243.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

These updated packages fix the following security issues:

* it was discovered that, when executing a new process, the clear_child_tid
pointer in the Linux kernel is not cleared. If this pointer points to a
writable portion of the memory of the new program, the kernel could corrupt
four bytes of memory, possibly leading to a local denial of service or
privilege escalation. (CVE-2009-2848, Important)

* a flaw was found in the way the do_sigaltstack() function in the Linux
kernel copies the stack_t structure to user-space. On 64-bit machines, this
flaw could lead to a four-byte information leak. (CVE-2009-2847, Moderate)

* a flaw was found in the ext4 file system code. A local attacker could use
this flaw to cause a denial of service by performing a resize operation on
a specially-crafted ext4 file system. (CVE-2009-0745, Low)

* multiple flaws were found in the ext4 file system code. A local attacker
could use these flaws to cause a denial of service by mounting a
specially-crafted ext4 file system. (CVE-2009-0746, CVE-2009-0747,
CVE-2009-0748, Low)

These updated packages also include several hundred bug fixes for and
enhancements to the Linux kernel. Space precludes documenting each of these
changes in this advisory and users are directed to the Red Hat Enterprise
Linux 5.4 Release Notes for information on the most significant of these
changes:


Also, for details concerning every bug fixed in and every enhancement added
to the kernel for this release, see the kernel chapter in the Red Hat
Enterprise Linux 5.4 Technical Notes:

http://www.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/5.4/html/
Technical_Notes/kernel.html

All Red Hat Enterprise Linux 5 users are advised to install these updated
packages, which address these vulnerabilities as well as fixing the bugs
and adding the enhancements noted in the Red Hat Enterprise Linux 5.4
Release Notes and Technical Notes. The system must be rebooted for this
update to take effect.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304385");
 script_version("$Revision: 6683 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-09-09 02:15:49 +0200 (Wed, 09 Sep 2009)");
 script_cve_id("CVE-2009-0745", "CVE-2009-0746", "CVE-2009-0747", "CVE-2009-0748", "CVE-2009-2847", "CVE-2009-2848");
 script_tag(name:"cvss_base", value:"4.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
 script_name("RedHat Security Advisory RHSA-2009:1243");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Red Hat Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 script_xref(name : "URL" , value : "http://www.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/5.4/html/");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~164.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~164.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAE-debuginfo", rpm:"kernel-PAE-debuginfo~2.6.18~164.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~164.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~164.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~2.6.18~164.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~164.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.18~164.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo-common", rpm:"kernel-debuginfo-common~2.6.18~164.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~164.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~164.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~164.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen-debuginfo", rpm:"kernel-xen-debuginfo~2.6.18~164.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~164.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~164.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-kdump", rpm:"kernel-kdump~2.6.18~164.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-kdump-debuginfo", rpm:"kernel-kdump-debuginfo~2.6.18~164.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-kdump-devel", rpm:"kernel-kdump-devel~2.6.18~164.el5", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
