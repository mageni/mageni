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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0308");
  script_cve_id("CVE-2022-1679", "CVE-2022-2585", "CVE-2022-2586", "CVE-2022-2588", "CVE-2022-26373", "CVE-2022-36946");
  script_tag(name:"creation_date", value:"2022-08-26 04:58:48 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T04:58:48+0000");
  script_tag(name:"last_modification", value:"2022-08-26 04:58:48 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-24 22:22:00 +0000 (Tue, 24 May 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0308)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0308");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0308.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30762");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30725");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.59");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.60");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.61");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.62");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2022-0308 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel update is based on upstream 5.15.62 and fixes at least the
following security issues:

A use-after-free flaw was found in the Linux kernel Atheros wireless adapter
driver in the way a user forces the ath9k_htc_wait_for_target function to
fail with some input messages. This flaw allows a local user to crash or
potentially escalate their privileges on the system (CVE-2022-1679).

A use-after-free flaw was found in the Linux kernel's POSIX CPU timers
functionality in the way a user creates and then deletes the timer in the
non-leader thread of the program. This flaw allows a local user to crash
or potentially escalate their privileges on the system (CVE-2022-2585).

A use-after-free flaw was found in nf_tables cross-table in the
net/netfilter/nf_tables_api.c function in the Linux kernel. This flaw allows
a local, privileged attacker to cause a use-after-free problem at the time
of table deletion, possibly leading to local privilege escalation
(CVE-2022-2586).

A use-after-free flaw was found in route4_change in the net/sched/cls_route.c
filter implementation in the Linux kernel. This flaw allows a local,
privileged attacker to crash the system, possibly leading to a local
privilege escalation issue (CVE-2022-2588).

A flaw was found in hw. In certain processors with Intel's Enhanced Indirect
Branch Restricted Speculation (eIBRS) capabilities, soon after VM exit or
IBPB command event, the linear address following the most recent near CALL
instruction prior to a VM exit may be used as the Return Stack Buffer (RSB)
prediction (CVE-2022-26373).

nfqnl_mangle in net/netfilter/nfnetlink_queue.c in the Linux kernel through
5.18.14 allows remote attackers to cause a denial of service (panic) because,
in the case of an nf_queue verdict with a one-byte nfta_payload attribute,
an skb_pull can encounter a negative skb->len (CVE-2022-36946).

x86/bugs: Enable STIBP for IBPB mitigated RETBleed.

Other fixes in this update:
- add support for more tcp congestion control algos (mga #30725)

For other upstream fixes in this update, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-linus' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.15.62-1.mga8", rpm:"kernel-linus-5.15.62-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.15.62~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.15.62-1.mga8", rpm:"kernel-linus-devel-5.15.62-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.15.62~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.15.62~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.15.62~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.15.62-1.mga8", rpm:"kernel-linus-source-5.15.62-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.15.62~1.mga8", rls:"MAGEIA8"))) {
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
