###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2013:0744 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.881723");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-04-25 10:23:07 +0530 (Thu, 25 Apr 2013)");
  script_cve_id("CVE-2012-6537", "CVE-2012-6546", "CVE-2012-6547", "CVE-2013-0349",
                "CVE-2013-0913", "CVE-2013-1767", "CVE-2013-1773", "CVE-2013-1774",
                "CVE-2013-1792", "CVE-2013-1796", "CVE-2013-1797", "CVE-2013-1798",
                "CVE-2013-1826", "CVE-2013-1827");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for kernel CESA-2013:0744 centos6");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-April/019701.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"kernel on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Security:

  * An integer overflow flaw, leading to a heap-based buffer overflow, was
  found in the way the Intel i915 driver in the Linux kernel handled the
  allocation of the buffer used for relocation copies. A local user with
  console access could use this flaw to cause a denial of service or escalate
  their privileges. (CVE-2013-0913, Important)

  * A buffer overflow flaw was found in the way UTF-8 characters were
  converted to UTF-16 in the utf8s_to_utf16s() function of the Linux kernel's
  FAT file system implementation. A local user able to mount a FAT file
  system with the 'utf8=1' option could use this flaw to crash the
  system or, potentially, to escalate their privileges. (CVE-2013-1773,
  Important)

  * A flaw was found in the way KVM handled guest time updates when the
  buffer the guest registered by writing to the MSR_KVM_SYSTEM_TIME machine
  state register (MSR) crossed a page boundary. A privileged guest user could
  use this flaw to crash the host or, potentially, escalate their privileges,
  allowing them to execute arbitrary code at the host kernel level.
  (CVE-2013-1796, Important)

  * A potential use-after-free flaw was found in the way KVM handled guest
  time updates when the GPA (guest physical address) the guest registered by
  writing to the MSR_KVM_SYSTEM_TIME machine state register (MSR) fell into a
  movable or removable memory region of the hosting user-space process (by
  default, QEMU-KVM) on the host. If that memory region is deregistered from
  KVM using KVM_SET_USER_MEMORY_REGION and the allocated virtual memory
  reused, a privileged guest user could potentially use this flaw to
  escalate their privileges on the host. (CVE-2013-1797, Important)

  * A flaw was found in the way KVM emulated IOAPIC (I/O Advanced
  Programmable Interrupt Controller). A missing validation check in the
  ioapic_read_indirect() function could allow a privileged guest user to
  crash the host, or read a substantial portion of host kernel memory.
  (CVE-2013-1798, Important)

  * A race condition in install_user_keyrings(), leading to a NULL pointer
  dereference, was found in the key management facility. A local,
  unprivileged user could use this flaw to cause a denial of service.
  (CVE-2013-1792, Moderate)

  * A NULL pointer dereference in the XFRM implementation could allow a local
  user who has the CAP_NET_ADMIN capability to cause a denial of service.
  (CVE-2013-1826, Moderate)

  * A NULL pointer dereference in the Datagram Congestion Control Protocol
  (DCCP) implementation could allow a local user to cause a denial of
  service. (CVE ...

  Description truncated, please see the referenced URL(s) for more information.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~358.6.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~358.6.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~358.6.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~358.6.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~358.6.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~358.6.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~358.6.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~358.6.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~358.6.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
