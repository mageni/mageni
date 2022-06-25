###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for kernel SUSE-SA:2011:002
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
  script_oid("1.3.6.1.4.1.25623.1.0.850156");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2011-01-11 16:07:49 +0100 (Tue, 11 Jan 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2010-3067", "CVE-2010-3437", "CVE-2010-3442", "CVE-2010-3861", "CVE-2010-3865", "CVE-2010-3874", "CVE-2010-4078", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4082", "CVE-2010-4157", "CVE-2010-4158", "CVE-2010-4160", "CVE-2010-4162", "CVE-2010-4163", "CVE-2010-4164", "CVE-2010-4165", "CVE-2010-4175", "CVE-2010-4258");
  script_name("SuSE Update for kernel SUSE-SA:2011:002");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE11\.2");
  script_tag(name:"impact", value:"potential local privilege escalation");
  script_tag(name:"affected", value:"kernel on openSUSE 11.2");
  script_tag(name:"insight", value:"This update of the openSUSE 11.2 kernel fixes various bugs
  and lots of security issues.

  Following security issues have been fixed:
  CVE-2010-4258: A local attacker could use a Oops (kernel crash) caused
  by other flaws to write a 0 byte to a attacker controlled address in the
  kernel. This could lead to privilege escalation together with other issues.

  CVE-2010-4160: A overflow in sendto() and recvfrom() routines was fixed
  that could be used by local attackers to potentially crash the kernel
  using some socket families like L2TP.

  CVE-2010-4157: A 32bit vs 64bit integer mismatch in gdth_ioctl_alloc
  could lead to memory corruption in the GDTH driver.

  CVE-2010-4165: The do_tcp_setsockopt function in net/ipv4/tcp.c in the
  Linux kernel did not properly restrict TCP_MAXSEG (aka MSS) values, which
  allows local users to cause a denial of service (OOPS) via a setsockopt
  call that specifies a small value, leading to a divide-by-zero error or
  incorrect use of a signed integer.

  CVE-2010-4164: A remote (or local) attacker communicating over X.25
  could cause a kernel panic by attempting to negotiate malformed
  facilities.

  CVE-2010-4175:  A local attacker could cause memory overruns in the RDS
  protocol stack, potentially crashing the kernel. So far it is considered
  not to be exploitable.

  CVE-2010-3874: A minor heap overflow in the CAN network module was fixed.
  Due to nature of the memory allocator it is likely not exploitable.

  CVE-2010-3874: A minor heap overflow in the CAN network module was fixed.
  Due to nature of the memory allocator it is likely not exploitable.

  CVE-2010-4158: A memory information leak in Berkeley packet filter rules
  allowed local attackers to read uninitialized memory of the kernel stack.

  CVE-2010-4162: A local denial of service in the blockdevice layer was fixed.

  CVE-2010-4163: By submitting certain I/O requests with 0 length, a local
  user could have caused a kernel panic.

  CVE-2010-3861: The ethtool_get_rxnfc function in net/core/ethtool.c
  in the Linux kernel did not initialize a certain block of heap memory,
  which allowed local users to obtain potentially sensitive information via
  an ETHTOOL_GRXCLSRLALL ethtool command with a large info.rule_cnt value.

  CVE-2010-3442: Multiple integer overflows in the snd_ctl_new function
  in sound/core/control.c in the Linux kernel allowed local users to
  cause a denial of service (heap memory corruption) or possibly have
  unspecified other impact via a crafted (1) SNDRV_CTL_IOCTL_ELEM_ADD or
  (2) SNDRV_CTL_IOCTL_ELEM_REPLACE ioctl ca ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE11.2")
{

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.31.14~0.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-base", rpm:"kernel-debug-base~2.6.31.14~0.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.31.14~0.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.31.14~0.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~2.6.31.14~0.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~2.6.31.14~0.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-desktop", rpm:"kernel-desktop~2.6.31.14~0.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-desktop-base", rpm:"kernel-desktop-base~2.6.31.14~0.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-desktop-devel", rpm:"kernel-desktop-devel~2.6.31.14~0.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.31.14~0.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~2.6.31.14~0.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~2.6.31.14~0.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.31.14~0.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~2.6.31.14~0.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~2.6.31.14~0.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~2.6.31.14~0.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~2.6.31.14~0.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~2.6.31.14~0.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla-devel", rpm:"kernel-vanilla-devel~2.6.31.14~0.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.31.14~0.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~2.6.31.14~0.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.31.14~0.6.1", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"preload-kmp-default", rpm:"preload-kmp-default~1.1_2.6.31.14_0.6~6.9.39", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"preload-kmp-desktop", rpm:"preload-kmp-desktop~1.1_2.6.31.14_0.6~6.9.39", rls:"openSUSE11.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
