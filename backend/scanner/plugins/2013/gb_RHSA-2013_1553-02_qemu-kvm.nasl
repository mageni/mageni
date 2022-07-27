###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for qemu-kvm RHSA-2013:1553-02
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871073");
  script_version("$Revision: 12382 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:51:56 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-11-21 10:43:53 +0530 (Thu, 21 Nov 2013)");
  script_cve_id("CVE-2013-4344");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_name("RedHat Update for qemu-kvm RHSA-2013:1553-02");


  script_tag(name:"affected", value:"qemu-kvm on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"insight", value:"KVM (Kernel-based Virtual Machine) is a full virtualization solution for
Linux on AMD64 and Intel 64 systems that is built into the standard Red Hat
Enterprise Linux kernel. The qemu-kvm packages form the user-space
component for running virtual machines using KVM.

A buffer overflow flaw was found in the way QEMU processed the SCSI 'REPORT
LUNS' command when more than 256 LUNs were specified for a single SCSI
target. A privileged guest user could use this flaw to corrupt QEMU process
memory on the host, which could potentially result in arbitrary code
execution on the host with the privileges of the QEMU process.
(CVE-2013-4344)

This issue was discovered by Asias He of Red Hat.

These updated qemu-kvm packages include numerous bug fixes and various
enhancements. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 6.5 Technical
Notes, linked to in the References, for information on the most significant
of these changes.

All qemu-kvm users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add these
enhancements. After installing this update, shut down all running virtual
machines. Once all virtual machines have shut down, start them again for
this update to take effect.

4. Solution:

Before applying this update, make sure all previously-released errata
relevant to your system have been applied.

This update is available via the Red Hat Network. Details on how to
use the Red Hat Network to apply this update are available at the references.

5. Bugs fixed:

670162 - [RFE] Removing the backing file using qemu-img re-base
796011 - Prompt error of trigger blkdebug: BLKDBG_CLUSTER_FREE event is not the same as expected
817066 - QEMU should disable VNC password auth when in FIPS 140-2 mode
821741 - (re-)enable SEP flag on CPU models
843797 - qemu-kvm core dumps when virtio-net(w/ tx=timer and vhost=on) RHEL.6(w/ msi-x enabled) guest shutting down
848070 - [RHEL 6.5] Add glusterfs support to qemu
856505 - Missing error message in bdrv_commit to read-only backing file
864378 - qemu-img convert fails with Floating Point Exception with zero length source image
869496 - screendump won't save PPM image file if qemu-kvm booted with '-S'
869586 - core dump happens when quitting ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-November/msg00021.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  script_xref(name:"URL", value:"https://access.redhat.com/site/articles/11258");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~0.12.1.2~2.415.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-debuginfo", rpm:"qemu-kvm-debuginfo~0.12.1.2~2.415.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.12.1.2~2.415.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~0.12.1.2~2.415.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~0.12.1.2~2.415.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
