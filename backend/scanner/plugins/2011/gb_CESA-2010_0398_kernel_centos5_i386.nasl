###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2010:0398 centos5 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-May/016683.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880586");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2010-0307", "CVE-2010-0410", "CVE-2010-0730", "CVE-2010-1085", "CVE-2010-1086");
  script_name("CentOS Update for kernel CESA-2010:0398 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"kernel on CentOS 5");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:

  * a flaw was found in the Unidirectional Lightweight Encapsulation (ULE)
  implementation. A remote attacker could send a specially-crafted ISO
  MPEG-2 Transport Stream (TS) frame to a target system, resulting in an
  infinite loop (denial of service). (CVE-2010-1086, Important)

  * on AMD64 systems, it was discovered that the kernel did not ensure the
  ELF interpreter was available before making a call to the SET_PERSONALITY
  macro. A local attacker could use this flaw to cause a denial of service by
  running a 32-bit application that attempts to execute a 64-bit application.
  (CVE-2010-0307, Moderate)

  * a flaw was found in the kernel connector implementation. A local,
  unprivileged user could trigger this flaw by sending an arbitrary number
  of notification requests using specially-crafted netlink messages,
  resulting in a denial of service. (CVE-2010-0410, Moderate)

  * a flaw was found in the Memory-mapped I/O (MMIO) instruction decoder in
  the Xen hypervisor implementation. An unprivileged guest user could use
  this flaw to trick the hypervisor into emulating a certain instruction,
  which could crash the guest (denial of service). (CVE-2010-0730, Moderate)

  * a divide-by-zero flaw was found in the azx_position_ok() function in the
  driver for Intel High Definition Audio, snd-hda-intel. A local,
  unprivileged user could trigger this flaw to cause a kernel crash (denial
  of service). (CVE-2010-1085, Moderate)

  This update also fixes the following bugs:

  * in some cases, booting a system with the 'iommu=on' kernel parameter
  resulted in a Xen hypervisor panic. (BZ#580199)

  * the fnic driver flushed the Rx queue instead of the Tx queue after
  fabric login. This caused crashes in some cases. (BZ#580829)

  * 'kernel unaligned access' warnings were logged to the dmesg log on some
  systems. (BZ#580832)

  * the 'Northbridge Error, node 1, core: -1 K8 ECC error' error occurred on
  some systems using the amd64_edac driver. (BZ#580836)

  * in rare circumstances, when using kdump and booting a kernel with
  'crashkernel=128M 16M', the kdump kernel did not boot after a crash.
  (BZ#580838)

  * TLB page table entry flushing was done incorrectly on IBM System z,
  possibly causing crashes, subtle data inconsistency, or other issues.
  (BZ#580839)

  * iSCSI failover times were slower than in Red Hat Enterprise Linux 5.3.
  (BZ#580840)

  * fixed floating point st ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~194.3.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~194.3.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~194.3.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~194.3.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~194.3.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~194.3.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~194.3.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~194.3.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~194.3.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~194.3.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
