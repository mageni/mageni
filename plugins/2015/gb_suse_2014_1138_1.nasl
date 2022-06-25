###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_1138_1.nasl 13941 2019-02-28 14:35:50Z cfischer $
#
# SuSE Update for the Linux Kernel SUSE-SU-2014:1138-1 (kernel)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850975");
  script_version("$Revision: 13941 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-28 15:35:50 +0100 (Thu, 28 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-10-16 15:20:35 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2013-1860", "CVE-2013-4162", "CVE-2013-7266", "CVE-2013-7267", "CVE-2013-7268", "CVE-2013-7269", "CVE-2013-7270", "CVE-2013-7271", "CVE-2014-0203", "CVE-2014-3144", "CVE-2014-3145", "CVE-2014-3917", "CVE-2014-4508", "CVE-2014-4652", "CVE-2014-4653", "CVE-2014-4654", "CVE-2014-4655", "CVE-2014-4656", "CVE-2014-4667", "CVE-2014-4699", "CVE-2014-4943", "CVE-2014-5077");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for the Linux Kernel SUSE-SU-2014:1138-1 (kernel)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The SUSE Linux Enterprise Server 11 SP1 LTSS received a roll up update to
  fix several security and non-security issues.

  The following security issues have been fixed:

  * CVE-2013-1860: Heap-based buffer overflow in the wdm_in_callback
  function in drivers/usb/class/cdc-wdm.c in the Linux kernel before
  3.8.4 allows physically proximate attackers to cause a denial of
  service (system crash) or possibly execute arbitrary code via a
  crafted cdc-wdm USB device. (bnc#806431)

  * CVE-2013-4162: The udp_v6_push_pending_frames function in
  net/ipv6/udp.c in the IPv6 implementation in the Linux kernel
  through 3.10.3 makes an incorrect function call for pending data,
  which allows local users to cause a denial of service (BUG and
  system crash) via a crafted application that uses the UDP_CORK
  option in a setsockopt system call. (bnc#831058)

  * CVE-2014-0203: The __do_follow_link function in fs/namei.c in the
  Linux kernel before 2.6.33 does not properly handle the last
  pathname component during use of certain filesystems, which allows
  local users to cause a denial of service (incorrect free operations
  and system crash) via an open system call. (bnc#883526)

  * CVE-2014-3144: The (1) BPF_S_ANC_NLATTR and (2)
  BPF_S_ANC_NLATTR_NEST extension implementations in the sk_run_filter
  function in net/core/filter.c in the Linux kernel through 3.14.3 do
  not check whether a certain length value is sufficiently large,
  which allows local users to cause a denial of service (integer
  underflow and system crash) via crafted BPF instructions. NOTE: the
  affected code was moved to the __skb_get_nlattr and
  __skb_get_nlattr_nest functions before the vulnerability was
  announced. (bnc#877257)

  * CVE-2014-3145: The BPF_S_ANC_NLATTR_NEST extension implementation in
  the sk_run_filter function in net/core/filter.c in the Linux kernel
  through 3.14.3 uses the reverse order in a certain subtraction,
  which allows local users to cause a denial of service (over-read and
  system crash) via crafted BPF instructions. NOTE: the affected code
  was moved to the __skb_get_nlattr_nest function before the
  vulnerability was announced. (bnc#877257)

  * CVE-2014-3917: kernel/auditsc.c in the Linux kernel through 3.14.5,
  when CONFIG_AUDITSYSCALL is enabled with certain syscall rules,
  allows local users to obtain potentially sensitive single-bit values
  from kernel memory or cause a denial of service (OOPS) via a large
  value of a syscall number. (bnc#880484)

  * CVE-2014-4508: arch/x86/kernel/entry_32.S in the Linux kernel
  through 3.15.1 on 32-bit x86 platforms, ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on SUSE Linux Enterprise Server 11 SP1 LTSS");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0SP1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLES11.0SP1")
{

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.32.59~0.15.2", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~2.6.32.59~0.15.2", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~2.6.32.59~0.15.2", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.32.59~0.15.2", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.32.59~0.15.2", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~2.6.32.59~0.15.2", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~2.6.32.59~0.15.2", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~2.6.32.59~0.15.2", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~2.6.32.59~0.15.2", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~2.6.32.59~0.15.2", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~2.6.32.59~0.15.2", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.32.59~0.15.2", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~2.6.32.59~0.15.2", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.32.59~0.15.2", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.0.3_21548_16_2.6.32.59_0.15~0.5.26", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-trace", rpm:"xen-kmp-trace~4.0.3_21548_16_2.6.32.59_0.15~0.5.26", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~2.6.32.59~0.15.2", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.32.59~0.15.2", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~2.6.32.59~0.15.2", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~2.6.32.59~0.15.2", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.0.3_21548_16_2.6.32.59_0.15~0.5.26", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
