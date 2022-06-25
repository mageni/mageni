###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2017:0036 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882629");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-01-13 05:42:33 +0100 (Fri, 13 Jan 2017)");
  script_cve_id("CVE-2016-4998", "CVE-2016-6828", "CVE-2016-7117");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kernel CESA-2017:0036 centos6");
  script_tag(name:"summary", value:"Check the version of kernel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux
kernel, the core of any Linux operating system.

Security Fix(es):

  * A use-after-free vulnerability was found in the kernels socket recvmmsg
subsystem. This may allow remote attackers to corrupt memory and may allow
execution of arbitrary code. This corruption takes place during the error
handling routines within __sys_recvmmsg() function. (CVE-2016-7117,
Important)

  * An out-of-bounds heap memory access leading to a Denial of Service, heap
disclosure, or further impact was found in setsockopt(). The function call
is normally restricted to root, however some processes with cap_sys_admin
may also be able to trigger this flaw in privileged container environments.
(CVE-2016-4998, Moderate)

  * A use-after-free vulnerability was found in tcp_xmit_retransmit_queue and
other tcp_* functions. This condition could allow an attacker to send an
incorrect selective acknowledgment to existing connections, possibly
resetting a connection. (CVE-2016-6828, Moderate)

Bug Fix(es):

  * When parallel NFS returned a file layout, a kernel crash sometimes
occurred. This update removes the call to the BUG_ON() function from a code
path of a client that returns the file layout. As a result, the kernel no
longer crashes in the described situation. (BZ#1385480)

  * When a guest virtual machine (VM) on Microsoft Hyper-V was set to crash
on a Nonmaskable Interrupt (NMI) that was injected from the host, this VM
became unresponsive and did not create the vmcore dump file. This update
applies a set of patches to the Virtual Machine Bus kernel driver
(hv_vmbus) that fix this bug. As a result, the VM now first creates and
saves the vmcore dump file and then reboots. (BZ#1385482)

  * From Red Hat Enterprise Linux 6.6 to 6.8, the IPv6 routing cache
occasionally showed incorrect values. This update fixes the DST_NOCOUNT
mechanism, and the IPv6 routing cache now shows correct values.
(BZ#1391974)

  * When using the ixgbe driver and the software Fibre Channel over Ethernet
(FCoE) stack, suboptimal performance in some cases occurred on systems with
a large number of CPUs. This update fixes the fc_exch_alloc() function to
try all the available exchange managers in the list for an available
exchange ID. This change avoids failing allocations, which previously led
to the host busy status. (BZ#1392818)

  * When the vmwgfx kernel module loads, it overrides the boot resolution
automatically. Consequently, users were not able to change the resolution
by manual setting of the kernel's 'vga=' parameter in the
/boot/grub/grub.conf file. This update adds the 'nomodeset' parameter,
which can be set in the /boot/gr ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-January/022206.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~642.13.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~642.13.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~642.13.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~642.13.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~642.13.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~642.13.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~642.13.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~642.13.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~642.13.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~642.13.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
