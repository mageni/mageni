# OpenVAS Vulnerability Test
# $Id: RHSA_2009_1157.nasl 6683 2017-07-12 09:41:57Z cfischer $
# Description: Auto-generated from advisory RHSA-2009:1157 ()
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
tag_solution = "Users should upgrade to these updated packages, which contain backported
patches to correct these issues. The system must be rebooted for this
update to take effect.

Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date";

tag_summary = "The remote host is missing updates announced in
advisory RHSA-2009:1157.

The kernel-rt packages contain the Linux kernel, the core of any Linux
operating system.

Security fixes:

* a flaw was found in the Intel PRO/1000 network driver in the Linux
kernel. Frames with sizes near the MTU of an interface may be split across
multiple hardware receive descriptors. Receipt of such a frame could leak
through a validation check, leading to a corruption of the length check. A
remote attacker could use this flaw to send a specially-crafted packet that
would cause a denial of service or code execution. (CVE-2009-1385,
Important)

* Michael Tokarev reported a flaw in the Realtek r8169 Ethernet driver in
the Linux kernel. This driver allowed interfaces using this driver to
receive frames larger than what could be handled. This could lead to a
remote denial of service or code execution. (CVE-2009-1389, Important)

* several flaws were found in the way the Linux kernel CIFS implementation
handles Unicode strings. CIFS clients convert Unicode strings sent by a
server to their local character sets, and then write those strings into
memory. If a malicious server sent a long enough string, it could write
past the end of the target memory region and corrupt other memory areas,
possibly leading to a denial of service or privilege escalation on the
client mounting the CIFS share. (CVE-2009-1633, Important)

* Frank Filz reported the NFSv4 client was missing a file permission check
for the execute bit in some situations. This could allow local,
unprivileged users to run non-executable files on NFSv4 mounted file
systems. (CVE-2009-1630, Moderate)

* a deadlock flaw was found in the Linux kernel splice implementation. This
deadlock could occur during interactions between the
generic_file_splice_write() and splice_from_pipe() functions, possibly
leading to a partial denial of service on the file system partition where
the deadlock occurs. (CVE-2009-1961, Moderate)";




if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.304449");
 script_version("$Revision: 6683 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
 script_cve_id("CVE-2009-1385", "CVE-2009-1389", "CVE-2009-1630", "CVE-2009-1633", "CVE-2009-1961");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_name("RedHat Security Advisory RHSA-2009:1157");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Red Hat Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2009-1157.html");
 script_xref(name : "URL" , value : "http://www.redhat.com/security/updates/classification/#important");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~2.6.24.7~126.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-debug", rpm:"kernel-rt-debug~2.6.24.7~126.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-debug-debuginfo", rpm:"kernel-rt-debug-debuginfo~2.6.24.7~126.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-debug-devel", rpm:"kernel-rt-debug-devel~2.6.24.7~126.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~2.6.24.7~126.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-debuginfo-common", rpm:"kernel-rt-debuginfo-common~2.6.24.7~126.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-devel", rpm:"kernel-rt-devel~2.6.24.7~126.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-trace", rpm:"kernel-rt-trace~2.6.24.7~126.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-trace-debuginfo", rpm:"kernel-rt-trace-debuginfo~2.6.24.7~126.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-trace-devel", rpm:"kernel-rt-trace-devel~2.6.24.7~126.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-vanilla", rpm:"kernel-rt-vanilla~2.6.24.7~126.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-vanilla-debuginfo", rpm:"kernel-rt-vanilla-debuginfo~2.6.24.7~126.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-vanilla-devel", rpm:"kernel-rt-vanilla-devel~2.6.24.7~126.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kernel-rt-doc", rpm:"kernel-rt-doc~2.6.24.7~126.el5rt", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
