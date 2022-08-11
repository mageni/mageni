###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for kernel RHSA-2011:1350-01
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-October/msg00001.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870628");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-07-09 10:35:28 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2011-1160", "CVE-2011-1745", "CVE-2011-1746", "CVE-2011-1833",
                "CVE-2011-2022", "CVE-2011-2484", "CVE-2011-2496", "CVE-2011-2521",
                "CVE-2011-2723", "CVE-2011-2898", "CVE-2011-2918");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for kernel RHSA-2011:1350-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"kernel on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:

  * Flaws in the AGPGART driver implementation when handling certain IOCTL
  commands could allow a local user to cause a denial of service or escalate
  their privileges. (CVE-2011-1745, CVE-2011-2022, Important)

  * An integer overflow flaw in agp_allocate_memory() could allow a local
  user to cause a denial of service or escalate their privileges.
  (CVE-2011-1746, Important)

  * A race condition flaw was found in the Linux kernel's eCryptfs
  implementation. A local attacker could use the mount.ecryptfs_private
  utility to mount (and then access) a directory they would otherwise not
  have access to. Note: To correct this issue, the RHSA-2011:1241
  ecryptfs-utils update, which provides the user-space part of the fix, must
  also be installed. (CVE-2011-1833, Moderate)

  * A denial of service flaw was found in the way the taskstats subsystem
  handled the registration of process exit handlers. A local, unprivileged
  user could register an unlimited amount of these handlers, leading to
  excessive CPU time and memory use. (CVE-2011-2484, Moderate)

  * A flaw was found in the way mapping expansions were handled. A local,
  unprivileged user could use this flaw to cause a wrapping condition,
  triggering a denial of service. (CVE-2011-2496, Moderate)

  * A flaw was found in the Linux kernel's Performance Events implementation.
  It could falsely lead the NMI (Non-Maskable Interrupt) Watchdog to detect a
  lockup and panic the system. A local, unprivileged user could use this flaw
  to cause a denial of service (kernel panic) using the perf tool.
  (CVE-2011-2521, Moderate)

  * A flaw in skb_gro_header_slow() in the Linux kernel could lead to GRO
  (Generic Receive Offload) fields being left in an inconsistent state. An
  attacker on the local network could use this flaw to trigger a denial of
  service. GRO is enabled by default in all network drivers that support it.
  (CVE-2011-2723, Moderate)

  * A flaw was found in the way the Linux kernel's Performance Events
  implementation handled PERF_COUNT_SW_CPU_CLOCK counter overflow. A local,
  unprivileged user could use this flaw to cause a denial of service.
  (CVE-2011-2918, Moderate)

  * A flaw was found in the Linux kernel's Trusted Platform Module (TPM)
  implementation. A local, unprivileged user could use this flaw to leak
  information to user-space. ( ...

  Description truncated, please see the referenced URL(s) for more information.");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~131.17.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~131.17.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~2.6.32~131.17.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~131.17.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.32~131.17.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-i686", rpm:"kernel-debuginfo-common-i686~2.6.32~131.17.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~131.17.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~131.17.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~131.17.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf-debuginfo", rpm:"perf-debuginfo~2.6.32~131.17.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~131.17.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~131.17.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~2.6.32~131.17.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
