# OpenVAS Vulnerability Test
# $Id: RHSA_2009_1472.nasl 6683 2017-07-12 09:41:57Z cfischer $
# Description: Auto-generated from advisory RHSA-2009:1472 ()
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
advisory RHSA-2009:1472.

Xen is an open source virtualization framework. Virtualization allows users
to run guest operating systems in virtual machines on top of a host
operating system.

The pyGrub boot loader did not honor the password option in the grub.conf
file for para-virtualized guests. Users with access to a guest's console
could use this flaw to bypass intended access restrictions and boot the
guest with arbitrary kernel boot options, allowing them to get root
privileges in the guest's operating system. With this update, pyGrub
correctly honors the password option in grub.conf for para-virtualized
guests. (CVE-2009-3525)

This update also fixes the following bugs:

* rebooting para-virtualized guests sometimes caused those guests to crash
due to a race condition in the xend node control daemon. This update fixes
this race condition so that rebooting guests no longer potentially causes
them to crash and fail to reboot. (BZ#525141)

* due to a race condition in the xend daemon, a guest could disappear from
the list of running guests following a reboot, even though the guest
rebooted successfully and was running. This update fixes this race
condition so that guests always reappear in the guest list following a
reboot. (BZ#525143)

* attempting to use PCI pass-through to para-virtualized guests on certain
kernels failed with a Function not implemented error message. As a
result, users requiring PCI pass-through on para-virtualized guests were
not able to update the xen packages without also updating the kernel and
thus requiring a reboot. These updated packages enable PCI pass-through for
para-virtualized guests so that users do not need to upgrade the kernel in
order to take advantage of PCI pass-through functionality. (BZ#525149)

All Xen users should upgrade to these updated packages, which contain
backported patches to correct these issues. After installing the updated
packages, the xend service must be restarted for this update to take
effect.";

tag_solution = "Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.306272");
 script_version("$Revision: 6683 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-10-06 02:49:40 +0200 (Tue, 06 Oct 2009)");
 script_cve_id("CVE-2009-3525");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("RedHat Security Advisory RHSA-2009:1472");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Red Hat Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2009-1472.html");
 script_xref(name : "URL" , value : "http://www.redhat.com/security/updates/classification/#moderate");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"xen-debuginfo", rpm:"xen-debuginfo~3.0.3~94.el5_4.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~3.0.3~94.el5_4.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xen", rpm:"xen~3.0.3~94.el5_4.1", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~3.0.3~94.el5_4.1", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
