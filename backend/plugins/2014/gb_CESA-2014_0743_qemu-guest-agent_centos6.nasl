###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for qemu-guest-agent CESA-2014:0743 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881953");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-06-17 10:03:59 +0530 (Tue, 17 Jun 2014)");
  script_cve_id("CVE-2013-4148", "CVE-2013-4151", "CVE-2013-4535", "CVE-2013-4536",
                "CVE-2013-4541", "CVE-2013-4542", "CVE-2013-6399", "CVE-2014-0182",
                "CVE-2014-2894", "CVE-2014-3461");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for qemu-guest-agent CESA-2014:0743 centos6");

  script_tag(name:"affected", value:"qemu-guest-agent on CentOS 6");
  script_tag(name:"insight", value:"KVM (Kernel-based Virtual Machine) is a full virtualization
solution for Linux on AMD64 and Intel 64 systems. The qemu-kvm package provides
the user-space component for running virtual machines using KVM.

Multiple buffer overflow, input validation, and out-of-bounds write flaws
were found in the way the virtio, virtio-net, virtio-scsi, and usb drivers
of QEMU handled state loading after migration. A user able to alter the
savevm data (either on the disk or over the wire during migration) could
use either of these flaws to corrupt QEMU process memory on the
(destination) host, which could potentially result in arbitrary code
execution on the host with the privileges of the QEMU process.
(CVE-2013-4148, CVE-2013-4151, CVE-2013-4535, CVE-2013-4536, CVE-2013-4541,
CVE-2013-4542, CVE-2013-6399, CVE-2014-0182, CVE-2014-3461)

An out-of-bounds memory access flaw was found in the way QEMU's IDE device
driver handled the execution of SMART EXECUTE OFFLINE commands.
A privileged guest user could use this flaw to corrupt QEMU process memory
on the host, which could potentially result in arbitrary code execution on
the host with the privileges of the QEMU process. (CVE-2014-2894)

The CVE-2013-4148, CVE-2013-4151, CVE-2013-4535, CVE-2013-4536,
CVE-2013-4541, CVE-2013-4542, CVE-2013-6399, CVE-2014-0182, and
CVE-2014-3461 issues were discovered by Michael S. Tsirkin of Red Hat,
Anthony Liguori, and Michael Roth.

This update also fixes the following bugs:

  * Previously, under certain circumstances, libvirt failed to start guests
which used a non-zero PCI domain and SR-IOV Virtual Functions (VFs), and
returned the following error message:

Cannot assign device inside non-zero PCI segment as this KVM module does not
support it.

This update fixes this issue and guests using the aforementioned
configuration no longer fail to start. (BZ#1099941)

  * Due to an incorrect initialization of the cpus_sts bitmap, which holds
the enablement status of a vCPU, libvirt could fail to start a guest with
an unusual vCPU topology (for example, a guest with three cores and two
sockets). With this update, the initialization of cpus_sts has been
corrected, and libvirt no longer fails to start the aforementioned guests.
(BZ#1100575)

All qemu-kvm users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing this
update, shut down all running virtual machines. Once all virtual machines
have shut down, start them again for this update to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-June/020364.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-guest-agent'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~0.12.1.2~2.415.el6_5.10", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.12.1.2~2.415.el6_5.10", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~0.12.1.2~2.415.el6_5.10", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~0.12.1.2~2.415.el6_5.10", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
