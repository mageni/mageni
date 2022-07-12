###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2018_0008_kernel_centos6.nasl 14058 2019-03-08 13:25:52Z cfischer $
#
# CentOS Update for kernel CESA-2018:0008 centos6
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
  script_oid("1.3.6.1.4.1.25623.1.0.882822");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-01-05 23:54:55 +0100 (Fri, 05 Jan 2018)");
  script_cve_id("CVE-2017-5753", "CVE-2017-5715", "CVE-2017-5754");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kernel CESA-2018:0008 centos6");
  script_tag(name:"summary", value:"Check the version of kernel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux
kernel, the core of any Linux operating system.

Security Fix(es):

An industry-wide issue was found in the way many modern microprocessor
designs have implemented speculative execution of instructions (a commonly
used performance optimization). There are three primary variants of the
issue which differ in the way the speculative execution can be exploited.

Note: This issue is present in hardware and cannot be fully fixed via
software update. The updated kernel packages provide software mitigation
for this hardware issue at a cost of potential performance penalty. Please
refer to References section for further information about this issue and
the performance impact.

In this update mitigations for x86-64 architecture are provided.

Variant CVE-2017-5753 triggers the speculative execution by performing a
bounds-check bypass. It relies on the presence of a precisely-defined
instruction sequence in the privileged code as well as the fact that memory
accesses may cause allocation into the microprocessor's data cache even for
speculatively executed instructions that never actually commit (retire). As
a result, an unprivileged attacker could use this flaw to cross the syscall
boundary and read privileged memory by conducting targeted cache
side-channel attacks. (CVE-2017-5753, Important)

Variant CVE-2017-5715 triggers the speculative execution by utilizing
branch target injection. It relies on the presence of a precisely-defined
instruction sequence in the privileged code as well as the fact that memory
accesses may cause allocation into the microprocessor's data cache even for
speculatively executed instructions that never actually commit (retire). As
a result, an unprivileged attacker could use this flaw to cross the syscall
and guest/host boundaries and read privileged memory by conducting targeted
cache side-channel attacks. (CVE-2017-5715, Important)

Variant CVE-2017-5754 relies on the fact that, on impacted microprocessors,
during speculative execution of instruction permission faults, exception
generation triggered by a faulting access is suppressed until the
retirement of the whole instruction block. In a combination with the fact
that memory accesses may populate the cache even when the block is being
dropped and never committed (executed), an unprivileged local attacker
could use this flaw to read privileged (kernel space) memory by conducting
targeted cache side-channel attacks. (CVE-2017-5754, Important)

Note: CVE-2017-5754 affects Intel x86-64 microprocessors. AMD x86-64
microprocessors are not affected by this issue.

Red Hat would like to thank Google Project Zero for reporting these issues.");
  script_tag(name:"affected", value:"kernel on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-January/022701.html");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~696.18.7.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~696.18.7.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~696.18.7.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~696.18.7.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~696.18.7.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~696.18.7.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~696.18.7.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~696.18.7.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~696.18.7.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~696.18.7.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
