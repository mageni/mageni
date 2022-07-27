###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for qemu-kvm RHSA-2012:0050-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-January/msg00017.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870661");
  script_version("$Revision: 14231 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-16 11:56:51 +0100 (Sat, 16 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-09 10:44:31 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2012-0029", "CVE-2011-4127");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_name("RedHat Update for qemu-kvm RHSA-2012:0050-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"qemu-kvm on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"KVM (Kernel-based Virtual Machine) is a full virtualization solution for
  Linux on AMD64 and Intel 64 systems. qemu-kvm is the user-space component
  for running virtual machines using KVM.

  A heap overflow flaw was found in the way QEMU-KVM emulated the e1000
  network interface card. A privileged guest user in a virtual machine whose
  network interface is configured to use the e1000 emulated driver could use
  this flaw to crash the host or, possibly, escalate their privileges on the
  host. (CVE-2012-0029)

  Red Hat would like to thank Nicolae Mogoreanu for reporting this issue.

  This update also fixes the following bug:

  * qemu-kvm has a 'scsi' option, to be used, for example, with the
  '-device' option:'-device virtio-blk-pci, drive=[drive name], scsi=off'.
  Previously, however, it only masked the feature bit, and did not reject
  SCSI commands if a malicious guest ignored the feature bit and issued a
  request. This update corrects this issue. The 'scsi=off' option can be
  used to mitigate the virtualization aspect of CVE-2011-4127 before the
  RHSA-2011:1849 kernel update is installed on the host.

  This mitigation is only required if you do not have the RHSA-2011:1849
  kernel update installed on the host and you are using raw format virtio
  disks backed by a partition or LVM volume.

  If you run guests by invoking /usr/libexec/qemu-kvm directly, use the
  '-global virtio-blk-pci.scsi=off' option to apply the mitigation. If you
  are using libvirt, as recommended by Red Hat, and have the RHBA-2012:0013
  libvirt update installed, no manual action is required: guests will
  automatically use 'scsi=off'. (BZ#767721)

  Note: After installing the RHSA-2011:1849 kernel update, SCSI requests
  issued by guests via the SG_IO IOCTL will not be passed to the underlying
  block device when using raw format virtio disks backed by a partition or
  LVM volume, even if 'scsi=on' is used.

  As well, this update adds the following enhancement:

  * Prior to this update, qemu-kvm was not built with RELRO or PIE support.
  qemu-kvm is now built with full RELRO and PIE support as a security
  enhancement. (BZ#767906)

  All users of qemu-kvm should upgrade to these updated packages, which
  correct these issues and add this enhancement. After installing this
  update, shut down all running virtual machines. Once all virtual machines
  have shut down, start them again for this update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.12.1.2~2.209.el6_2.4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~0.12.1.2~2.209.el6_2.4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-debuginfo", rpm:"qemu-kvm-debuginfo~0.12.1.2~2.209.el6_2.4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~0.12.1.2~2.209.el6_2.4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
