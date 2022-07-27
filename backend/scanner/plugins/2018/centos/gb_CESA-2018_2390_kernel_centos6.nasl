###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2018_2390_kernel_centos6.nasl 14058 2019-03-08 13:25:52Z cfischer $
#
# CentOS Update for kernel CESA-2018:2390 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882936");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-08-15 06:18:58 +0200 (Wed, 15 Aug 2018)");
  script_cve_id("CVE-2017-0861", "CVE-2017-15265", "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-3693", "CVE-2018-7566", "CVE-2018-10901", "CVE-2018-1000004");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kernel CESA-2018:2390 centos6");
  script_tag(name:"summary", value:"Check the version of kernel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es):

  * Modern operating systems implement virtualization of physical memory to
efficiently use available system resources and provide inter-domain
protection through access control and isolation. The L1TF issue was found
in the way the x86 microprocessor designs have implemented speculative
execution of instructions (a commonly used performance optimisation) in
combination with handling of page-faults caused by terminated virtual to
physical address resolving process. As a result, an unprivileged attacker
could use this flaw to read privileged memory of the kernel or other
processes and/or cross guest/host boundaries to read host memory by
conducting targeted cache side-channel attacks. (CVE-2018-3620,
CVE-2018-3646)

  * An industry-wide issue was found in the way many modern microprocessor
designs have implemented speculative execution of instructions past bounds
check. The flaw relies on the presence of a precisely-defined instruction
sequence in the privileged code and the fact that memory writes occur to an
address which depends on the untrusted value. Such writes cause an update
into the microprocessor's data cache even for speculatively executed
instructions that never actually commit (retire). As a result, an
unprivileged attacker could use this flaw to influence speculative
execution and/or read privileged memory by conducting targeted cache
side-channel attacks. (CVE-2018-3693)

  * kernel: kvm: vmx: host GDT limit corruption (CVE-2018-10901)

  * kernel: Use-after-free in snd_pcm_info function in ALSA subsystem
potentially leads to privilege escalation (CVE-2017-0861)

  * kernel: Use-after-free in snd_seq_ioctl_create_port() (CVE-2017-15265)

  * kernel: race condition in snd_seq_write() may lead to UAF or OOB-access
(CVE-2018-7566)

  * kernel: Race condition in sound system can lead to denial of service
(CVE-2018-1000004)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank Intel OSSIRT (Intel.com) for reporting
CVE-2018-3620 and CVE-2018-3646  Vladimir Kiriansky (MIT) and Carl
Waldspurger (Carl Waldspurger Consulting) for reporting CVE-2018-3693  and
Vegard Nossum (Oracle Corporation) for reporting CVE-2018-10901.

Bug Fix(es):

  * The Least recently used (LRU) operations are batched by caching pages in
per-cpu page vectors to prevent contention of the heavily used lru_lock
spinlock. The page vectors can hold even the compound pages. Previously,
the  ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-August/022983.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~754.3.5.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~754.3.5.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~754.3.5.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~754.3.5.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~754.3.5.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~754.3.5.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~754.3.5.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~754.3.5.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~754.3.5.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~754.3.5.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
