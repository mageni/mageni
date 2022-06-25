###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2015:0864 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882174");
  script_version("$Revision: 14058 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-04-23 07:33:49 +0200 (Thu, 23 Apr 2015)");
  script_cve_id("CVE-2014-3215", "CVE-2014-3690", "CVE-2014-7825", "CVE-2014-7826",
                "CVE-2014-8171", "CVE-2014-8884", "CVE-2014-9529", "CVE-2014-9584",
                "CVE-2015-1421");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kernel CESA-2015:0864 centos6");
  script_tag(name:"summary", value:"Check the version of kernel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux
  kernel, the core of any Linux operating system.

  * A flaw was found in the way seunshare, a utility for running executables
under a different security context, used the capng_lock functionality of
the libcap-ng library. The subsequent invocation of suid root binaries that
relied on the fact that the setuid() system call, among others, also sets
the saved set-user-ID when dropping the binaries' process privileges, could
allow a local, unprivileged user to potentially escalate their privileges
on the system. Note: the fix for this issue is the kernel part of the
overall fix, and introduces the PR_SET_NO_NEW_PRIVS functionality and the
related SELinux exec transitions support. (CVE-2014-3215, Important)

  * A use-after-free flaw was found in the way the Linux kernel's SCTP
implementation handled authentication key reference counting during INIT
collisions. A remote attacker could use this flaw to crash the system or,
potentially, escalate their privileges on the system. (CVE-2015-1421,
Important)

  * It was found that the Linux kernel's KVM implementation did not ensure
that the host CR4 control register value remained unchanged across VM
entries on the same virtual CPU. A local, unprivileged user could use this
flaw to cause a denial of service on the system. (CVE-2014-3690, Moderate)

  * An out-of-bounds memory access flaw was found in the syscall tracing
functionality of the Linux kernel's perf subsystem. A local, unprivileged
user could use this flaw to crash the system. (CVE-2014-7825, Moderate)

  * An out-of-bounds memory access flaw was found in the syscall tracing
functionality of the Linux kernel's ftrace subsystem. On a system with
ftrace syscall tracing enabled, a local, unprivileged user could use this
flaw to crash the system, or escalate their privileges. (CVE-2014-7826,
Moderate)

  * It was found that the Linux kernel memory resource controller's (memcg)
handling of OOM (out of memory) conditions could lead to deadlocks.
An attacker able to continuously spawn new processes within a single
memory-constrained cgroup during an OOM event could use this flaw to lock
up the system. (CVE-2014-8171, Moderate)

  * A race condition flaw was found in the way the Linux kernel keys
management subsystem performed key garbage collection. A local attacker
could attempt accessing a key while it was being garbage collected, which
would cause the system to crash. (CVE-2014-9529, Moderate)

  * A stack-based buffer overflow flaw was found in the TechnoTrend/Hauppauge
DEC USB device driver. A local user with write access to the corresponding
device could use this flaw to crash ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-April/021083.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~504.16.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~504.16.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~504.16.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~504.16.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~504.16.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~504.16.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~504.16.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~504.16.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~504.16.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~504.16.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
