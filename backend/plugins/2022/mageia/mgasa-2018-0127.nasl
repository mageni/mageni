# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0127");
  script_cve_id("CVE-2017-1000410", "CVE-2017-15129", "CVE-2017-17741", "CVE-2017-5715", "CVE-2017-5753");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-31T07:41:30+0000");
  script_tag(name:"last_modification", value:"2022-01-31 07:41:30 +0000 (Mon, 31 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-08 20:29:00 +0000 (Mon, 08 Apr 2019)");

  script_name("Mageia: Security Advisory (MGASA-2018-0127)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0127");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0127.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22544");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.14");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.15");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.16");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.17");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.18");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2018-0127 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on the upstream 4.14.18 and adds some
support for mitigating Spectre, variant 1 (CVE-2017-5753) and as it is
built with the retpoline-aware gcc-5.5.0-1.mga6, it now provides full
retpoline mitigation for Spectre, variant 2 (CVE-2017-5715).

The BPF interpreter has been used as part of the spectre 2 attack
CVE-2017-5715. To make attacker job harder introduce BPF_JIT_ALWAYS_ON
config option that removes interpreter from the kernel in favor of JIT-only
mode. This is now enabled by default in Mageia kernels.

Other security fixes in this update:

Linux kernel version 3.3-rc1 and later is affected by a vulnerability lies
in the processing of incoming L2CAP commands - ConfigRequest, and
ConfigResponse messages. This info leak is a result of uninitialized stack
variables that may be returned to an attacker in their uninitialized state.
By manipulating the code flows that precede the handling of these
configuration messages, an attacker can also gain some control over which
data will be held in the uninitialized stack variables. This can allow him
to bypass KASLR, and stack canaries protection - as both pointers and stack
canaries may be leaked in this manner (CVE-2017-1000410).

A use-after-free vulnerability was found in network namespaces code
affecting the Linux kernel before 4.14.11. The function get_net_ns_by_id()
in net/core/net_namespace.c does not check for the net::count value after
it has found a peer network in netns_ids idr, which could lead to double
free and memory corruption. This vulnerability could allow an unprivileged
local user to induce kernel memory corruption on the system, leading to a
crash. Due to the nature of the flaw, privilege escalation cannot be fully
ruled out, although it is thought to be unlikely (CVE-2017-15129).

The KVM implementation in the Linux kernel through 4.14.7 allows attackers
to obtain potentially sensitive information from kernel memory, aka a
write_mmio stack-based out-of-bounds read, related to arch/x86/kvm/x86.c
and include/trace/events/kvm.h (CVE-2017-17741).

For other fixes in this update, read the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-4.14.18-1.mga6", rpm:"kernel-linus-4.14.18-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~4.14.18~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-4.14.18-1.mga6", rpm:"kernel-linus-devel-4.14.18-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~4.14.18~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~4.14.18~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~4.14.18~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-4.14.18-1.mga6", rpm:"kernel-linus-source-4.14.18-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~4.14.18~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
