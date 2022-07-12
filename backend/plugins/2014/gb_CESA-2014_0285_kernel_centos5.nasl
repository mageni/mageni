###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2014:0285 centos5
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
  script_oid("1.3.6.1.4.1.25623.1.0.881900");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-03-17 13:13:37 +0530 (Mon, 17 Mar 2014)");
  script_cve_id("CVE-2013-2929", "CVE-2013-4483", "CVE-2013-4554", "CVE-2013-6381",
                "CVE-2013-6383", "CVE-2013-6885", "CVE-2013-7263", "CVE-2013-7265");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for kernel CESA-2014:0285 centos5");

  script_tag(name:"affected", value:"kernel on CentOS 5");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

  * A buffer overflow flaw was found in the way the qeth_snmp_command()
function in the Linux kernel's QETH network device driver implementation
handled SNMP IOCTL requests with an out-of-bounds length. A local,
unprivileged user could use this flaw to crash the system or, potentially,
escalate their privileges on the system. (CVE-2013-6381, Important)

  * A flaw was found in the way the ipc_rcu_putref() function in the Linux
kernel's IPC implementation handled reference counter decrementing.
A local, unprivileged user could use this flaw to trigger an Out of Memory
(OOM) condition and, potentially, crash the system. (CVE-2013-4483,
Moderate)

  * It was found that the Xen hypervisor implementation did not correctly
check privileges of hypercall attempts made by HVM guests, allowing
hypercalls to be invoked from protection rings 1 and 2 in addition to ring
0. A local attacker in an HVM guest able to execute code on privilege
levels 1 and 2 could potentially use this flaw to further escalate their
privileges in that guest. Note: Xen HVM guests running unmodified versions
of Red Hat Enterprise Linux and Microsoft Windows are not affected by this
issue because they are known to only use protection rings 0 (kernel) and 3
(userspace). (CVE-2013-4554, Moderate)

  * A flaw was found in the way the Linux kernel's Adaptec RAID controller
(aacraid) checked permissions of compat IOCTLs. A local attacker could use
this flaw to bypass intended security restrictions. (CVE-2013-6383,
Moderate)

  * It was found that, under specific circumstances, a combination of write
operations to write-combined memory and locked CPU instructions may cause a
core hang on certain AMD CPUs (for more information, refer to AMD CPU
erratum 793 linked in the References section). A privileged user in a guest
running under the Xen hypervisor could use this flaw to cause a denial of
service on the host system. This update adds a workaround to the Xen
hypervisor implementation, which mitigates the AMD CPU issue. Note: this
issue only affects AMD Family 16h Models 00h-0Fh Processors. Non-AMD CPUs
are not vulnerable. (CVE-2013-6885, Moderate)

  * It was found that certain protocol handlers in the Linux kernel's
networking implementation could set the addr_len value without initializing
the associated data structure. A local, unprivileged user could use this
flaw to leak kernel stack memory to user space using the recvmsg, recvfrom,
and recvmmsg system calls. (CVE-2013-7263, Low)

  * A flaw was found in the way the get_dumpable() function return value was
interpre ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-March/020199.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~371.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~371.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~371.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~371.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~371.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~371.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~371.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~371.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~371.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~371.6.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
