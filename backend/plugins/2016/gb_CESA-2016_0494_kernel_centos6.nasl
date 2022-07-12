###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2016:0494 centos6
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
  script_oid("1.3.6.1.4.1.25623.1.0.882433");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-03-24 06:15:00 +0100 (Thu, 24 Mar 2016)");
  script_cve_id("CVE-2016-0774", "CVE-2015-1805");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kernel CESA-2016:0494 centos6");
  script_tag(name:"summary", value:"Check the version of kernel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux
kernel, the core of any Linux operating system.

  * It was found that the fix for CVE-2015-1805 incorrectly kept buffer
offset and buffer length in sync on a failed atomic read, potentially
resulting in a pipe buffer state corruption. A local, unprivileged user
could use this flaw to crash the system or leak kernel memory to user
space. (CVE-2016-0774, Moderate)

The security impact of this issue was discovered by Red Hat.

This update also fixes the following bugs:

  * In the anon_vma structure, the degree counts number of child anon_vmas
and of VMAs which points to this anon_vma. Failure to decrement the
parent's degree in the unlink_anon_vma() function, when its list was empty,
previously triggered a BUG_ON() assertion. The provided patch makes sure
the anon_vma degree is always decremented when the VMA list is empty, thus
fixing this bug. (BZ#1318364)

  * When running Internet Protocol Security (IPSEC) on external storage
encrypted with LUKS under a substantial load on the system, data
corruptions could previously occur. A set of upstream patches has been
provided, and data corruption is no longer reported in this situation.
(BZ#1298994)

  * Due to prematurely decremented calc_load_task, the calculated load
average was off by up to the number of CPUs in the machine. As a
consequence, job scheduling worked improperly causing a drop in the system
performance. This update keeps the delta of the CPU going into NO_HZ idle
separately, and folds the pending idle delta into the global active count
while correctly aging the averages for the idle-duration when leaving NO_HZ
mode. Now, job scheduling works correctly, ensuring balanced CPU load.
(BZ#1300349)

  * Due to a regression in the Red Hat Enterprise Linux 6.7 kernel, the
cgroup OOM notifier accessed a cgroup-specific internal data structure
without a proper locking protection, which led to a kernel panic. This
update adjusts the cgroup OOM notifier to lock internal data properly,
thus fixing the bug. (BZ#1302763)

  * GFS2 had a rare timing window that sometimes caused it to reference an
uninitialized variable. Consequently, a kernel panic occurred. The code has
been changed to reference the correct value during this timing window, and
the kernel no longer panics. (BZ#1304332)

  * Due to a race condition whereby a cache operation could be submitted
after a cache object was killed, the kernel occasionally crashed on systems
running the cachefilesd service. The provided patch prevents the race
condition by adding serialization in the code that makes the object
unavailable. As a result, all subsequent operations targette ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-March/021769.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~573.22.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~573.22.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~573.22.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~573.22.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~573.22.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~573.22.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~573.22.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~573.22.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~573.22.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~573.22.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
