# OpenVAS Vulnerability Test
# $Id: RHSA_2009_0003.nasl 6683 2017-07-12 09:41:57Z cfischer $
# Description: Auto-generated from advisory RHSA-2009:0003 ()
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
advisory RHSA-2009:0003.

The xen packages contain the Xen tools and management daemons needed to
manage virtual machines running on Red Hat Enterprise Linux.

Xen was found to allow unprivileged DomU domains to overwrite xenstore
values which should only be changeable by the privileged Dom0 domain. An
attacker controlling a DomU domain could, potentially, use this flaw to
kill arbitrary processes in Dom0 or trick a Dom0 user into accessing the
text console of a different domain running on the same host. This update
makes certain parts of the xenstore tree read-only to the unprivileged DomU
domains. (CVE-2008-4405)

It was discovered that the qemu-dm.debug script created a temporary file in
/tmp in an insecure way. A local attacker in Dom0 could, potentially, use
this flaw to overwrite arbitrary files via a symlink attack. Note: This
script is not needed in production deployments and therefore was removed
and is not shipped with updated xen packages. (CVE-2008-4993)

This update also fixes the following bug:

* xen calculates its running time by adding the hypervisor's up-time to the
hypervisor's boot-time record. In live migrations of para-virtualized
guests, however, the guest would over-write the new hypervisor's boot-time
record with the boot-time of the previous hypervisor. This caused
time-dependent processes on the guests to fail (for example, crond would
fail to start cron jobs). With this update, the new hypervisor's boot-time
record is no longer over-written during live migrations.

All xen users are advised to upgrade to these updated packages, which
contain backported patches to resolve these issues. The Xen host must be
restarted for the update to take effect.";

tag_solution = "Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.306908");
 script_version("$Revision: 6683 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-01-07 23:16:01 +0100 (Wed, 07 Jan 2009)");
 script_cve_id("CVE-2008-4405", "CVE-2008-4993");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_name("RedHat Security Advisory RHSA-2009:0003");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Red Hat Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2009-0003.html");
 script_xref(name : "URL" , value : "http://www.redhat.com/security/updates/classification/#moderate");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"xen-debuginfo", rpm:"xen-debuginfo~3.0.3~64.el5_2.9", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~3.0.3~64.el5_2.9", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xen", rpm:"xen~3.0.3~64.el5_2.9", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~3.0.3~64.el5_2.9", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
