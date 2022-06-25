###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2016:1033 centos7
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882493");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-05-17 13:39:35 +0200 (Tue, 17 May 2016)");
  script_cve_id("CVE-2016-0758");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kernel CESA-2016:1033 centos7");
  script_tag(name:"summary", value:"Check the version of kernel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the
Linux kernel, the core of any Linux operating system.

Security Fix(es):

  * A flaw was found in the way the Linux kernel's ASN.1 DER decoder
processed certain certificate files with tags of indefinite length. A
local, unprivileged user could use a specially crafted X.509 certificate
DER file to crash the system or, potentially, escalate their privileges on
the system. (CVE-2016-0758, Important)

Red Hat would like to thank Philip Pettersson of Samsung for reporting this
issue.

Bug Fix(es):

  * Under certain conditions, the migration threads could race with the CPU
hotplug, which could cause a deadlock. A set of patches has been provided
to fix this bug, and the deadlock no longer occurs in the system.
(BZ#1299338)

  * A bug in the code that cleans up revoked delegations could previously
cause a soft lockup in the NFS server. This patch fixes the underlying
source code, so the lockup no longer occurs. (BZ#1311582)

  * The second attempt to reload Common Application Programming Interface
(CAPI) devices on the little-endian variant of IBM Power Systems previously
failed. The provided set of patches fixes this bug, and reloading works as
intended. (BZ#1312396)

  * Due to inconsistencies in page size of IOMMU, the NVMe device, and the
kernel, the BUG_ON signal previously occurred in the nvme_setup_prps()
function, leading to the system crash while setting up the DMA transfer.
The provided patch sets the default NVMe page size to 4k, thus preventing
the system crash. (BZ#1312399)

  * Previously, on a system using the Infiniband mlx5 driver used for the SRP
stack, a hard lockup previously occurred after the kernel exceeded time
with lock held with interrupts blocked. As a consequence, the system
panicked. This update fixes this bug, and the system no longer panics in
this situation. (BZ#1313814)

  * On the little-endian variant of IBM Power Systems, the kernel previously
crashed in the bitmap_weight() function while running the memory affinity
script. The provided patch fortifies the topology setup and prevents
sd- child from being set to NULL when it is already NULL. As a result, the
memory affinity script runs successfully. (BZ#1316158)

  * When a KVM guest wrote random values to the special-purpose registers
(SPR) Instruction Authority Mask Register (IAMR), the guest and the
corresponding QEMU process previously hung. This update adds the code which
sets SPRs to a suitable neutral value on guest exit, thus fixing this bug.
(BZ#1316636)

  * Under heavy iSCSI traffic load, the system previously panicked due to a
race in the locking code leading to a list corruption. This update  ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-May/021878.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~327.18.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~327.18.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~327.18.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~327.18.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~327.18.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~327.18.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~327.18.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~327.18.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~327.18.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~327.18.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~327.18.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~327.18.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
