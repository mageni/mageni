###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_0581_1.nasl 13941 2019-02-28 14:35:50Z cfischer $
#
# SuSE Update for the Linux Kernel SUSE-SU-2015:0581-1 (kernel)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850817");
  script_version("$Revision: 13941 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-28 15:35:50 +0100 (Thu, 28 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-10-13 16:47:33 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2013-7263", "CVE-2014-0181", "CVE-2014-3687", "CVE-2014-3688",
                "CVE-2014-3690", "CVE-2014-4608", "CVE-2014-7822", "CVE-2014-7842",
                "CVE-2014-7970", "CVE-2014-8133", "CVE-2014-8134", "CVE-2014-8160",
                "CVE-2014-8369", "CVE-2014-8559", "CVE-2014-9090", "CVE-2014-9322",
                "CVE-2014-9419", "CVE-2014-9420", "CVE-2014-9584", "CVE-2014-9585",
                "CVE-2015-1593", "CVE-2014-3601", "CVE-2010-5313");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for the Linux Kernel SUSE-SU-2015:0581-1 (kernel)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP3 kernel has been updated to receive
  various security and bugfixes.

  New features enabled:

  * The Ceph and rbd remote network block device drivers are now enabled
  and supported, to serve as client for SUSE Enterprise Storage 1.0.
  (FATE#318328)

  * Support to selected Bay Trail CPUs used in Point of Service Hardware
  was enabled. (FATE#317933)

  * Broadwell Legacy Audio, HDMI Audio and DisplayPort Audio support
  (Audio Driver: HD-A HDMI/DP Audio/HDA Analog/DSP) was enabled.
  (FATE#317347)

  The following security bugs have been fixed:

  * CVE-2015-1593: An integer overflow in the stack randomization on
  64-bit systems lead to less effective stack ASLR on those systems.
  (bsc#917839)

  * CVE-2014-8160: iptables rules could be bypassed if the specific
  network protocol module was not loaded, allowing e.g. SCTP to bypass
  the firewall if the sctp protocol was not enabled. (bsc#913059)

  * CVE-2014-7822: A flaw was found in the way the Linux kernels
  splice() system call validated its parameters. On certain file
  systems, a local, unprivileged user could have used this flaw to
  write past the maximum file size, and thus crash the system.
  (bnc#915322)

  * CVE-2014-9419: The __switch_to function in
  arch/x86/kernel/process_64.c in the Linux kernel did not ensure that
  Thread Local Storage (TLS) descriptors are loaded before proceeding
  with other steps, which made it easier for local users to bypass the
  ASLR protection mechanism via a crafted application that reads a TLS
  base address (bnc#911326).

  * CVE-2014-9584: The parse_rock_ridge_inode_internal function in
  fs/isofs/rock.c in the Linux kernel did not validate a length value
  in the Extensions Reference (ER) System Use Field, which allowed
  local users to obtain sensitive information from kernel memory via a
  crafted iso9660 image (bnc#912654).

  * CVE-2014-9585: The vdso_addr function in arch/x86/vdso/vma.c in the
  Linux kernel did not properly choose memory locations for the vDSO
  area, which made it easier for local users to bypass the ASLR
  protection mechanism by guessing a location at the end of a PMD
  (bnc#912705).

  * CVE-2014-8559: The d_walk function in fs/dcache.c in the Linux
  kernel did not properly maintain the semantics of rename_lock, which
  allowed local users to cause a denial of service (deadlock and
  system hang) via a crafted application (bnc#903640).

  * CVE-2014-9420: The rock_continue function in fs/isofs/rock.c in the
  Linux kernel did not restrict the number of Rock Ridge continuation
  entries, which allowed local users to ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on SUSE Linux Enterprise Server 11 SP3");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0SP3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLES11.0SP3")
{

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~0.47.50.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~0.47.50.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~0.47.50.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~0.47.50.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~0.47.50.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~0.47.50.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~0.47.50.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~0.47.50.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~0.47.50.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~0.47.50.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~0.47.50.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~0.47.50.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~0.47.50.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~0.47.50.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.2.5_04_3.0.101_0.47.50~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~3.0.101~0.47.50.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-bigsmp-base", rpm:"kernel-bigsmp-base~3.0.101~0.47.50.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-bigsmp-devel", rpm:"kernel-bigsmp-devel~3.0.101~0.47.50.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~0.47.50.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~0.47.50.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~0.47.50.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~0.47.50.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~0.47.50.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~0.47.50.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~0.47.50.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.2.5_04_3.0.101_0.47.50~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
