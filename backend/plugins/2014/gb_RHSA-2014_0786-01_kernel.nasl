###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for kernel RHSA-2014:0786-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871193");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2014-07-01 23:01:59 +0530 (Tue, 01 Jul 2014)");
  script_cve_id("CVE-2014-0206", "CVE-2014-1737", "CVE-2014-1738", "CVE-2014-2568",
                "CVE-2014-2851", "CVE-2014-3144", "CVE-2014-3145", "CVE-2014-3153");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for kernel RHSA-2014:0786-01");


  script_tag(name:"affected", value:"kernel on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

  * A flaw was found in the way the Linux kernel's futex subsystem handled
the requeuing of certain Priority Inheritance (PI) futexes. A local,
unprivileged user could use this flaw to escalate their privileges on the
system. (CVE-2014-3153, Important)

  * A use-after-free flaw was found in the way the ping_init_sock() function
of the Linux kernel handled the group_info reference counter. A local,
unprivileged user could use this flaw to crash the system or, potentially,
escalate their privileges on the system. (CVE-2014-2851, Important)

  * Use-after-free and information leak flaws were found in the way the
Linux kernel's floppy driver processed the FDRAWCMD IOCTL command. A local
user with write access to /dev/fdX could use these flaws to escalate their
privileges on the system. (CVE-2014-1737, CVE-2014-1738, Important)

  * It was found that the aio_read_events_ring() function of the Linux
kernel's Asynchronous I/O (AIO) subsystem did not properly sanitize the AIO
ring head received from user space. A local, unprivileged user could use
this flaw to disclose random parts of the (physical) memory belonging to
the kernel and/or other processes. (CVE-2014-0206, Moderate)

  * An out-of-bounds memory access flaw was found in the Netlink Attribute
extension of the Berkeley Packet Filter (BPF) interpreter functionality in
the Linux kernel's networking implementation. A local, unprivileged user
could use this flaw to crash the system or leak kernel memory to user space
via a specially crafted socket filter. (CVE-2014-3144, CVE-2014-3145,
Moderate)

  * An information leak flaw was found in the way the skb_zerocopy() function
copied socket buffers (skb) that are backed by user-space buffers (for
example vhost-net and Xen netback), potentially allowing an attacker to
read data from those buffers. (CVE-2014-2568, Low)

Red Hat would like to thank Kees Cook of Google for reporting
CVE-2014-3153 and Matthew Daley for reporting CVE-2014-1737 and
CVE-2014-1738. Google acknowledges Pinkie Pie as the original reporter of
CVE-2014-3153. The CVE-2014-0206 issue was discovered by Mateusz Guzik of
Red Hat.

This update also fixes the following bugs:

  * Due to incorrect calculation of Tx statistics in the qlcninc driver,
running the 'ethtool -S ethX' command could trigger memory corruption.
As a consequence, running the sosreport tool, that uses this command,
resulted in a kernel panic. The problem has been fixed by correcting the
said statistics calculation. (BZ#1104972)

  * When an attempt to create a file on  ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-June/msg00046.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~123.4.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~123.4.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~123.4.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~3.10.0~123.4.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~123.4.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~3.10.0~123.4.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~3.10.0~123.4.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~123.4.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~123.4.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~123.4.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-debuginfo", rpm:"kernel-tools-debuginfo~3.10.0~123.4.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~123.4.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~123.4.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf-debuginfo", rpm:"perf-debuginfo~3.10.0~123.4.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf-debuginfo", rpm:"python-perf-debuginfo~3.10.0~123.4.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
