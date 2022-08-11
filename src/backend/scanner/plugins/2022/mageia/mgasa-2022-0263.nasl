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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0263");
  script_cve_id("CVE-2022-2318", "CVE-2022-26365", "CVE-2022-33740", "CVE-2022-33741", "CVE-2022-33742", "CVE-2022-33743", "CVE-2022-33744", "CVE-2022-34918");
  script_tag(name:"creation_date", value:"2022-07-21 04:43:01 +0000 (Thu, 21 Jul 2022)");
  script_version("2022-07-21T04:43:01+0000");
  script_tag(name:"last_modification", value:"2022-07-21 04:43:01 +0000 (Thu, 21 Jul 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-13 14:00:00 +0000 (Wed, 13 Jul 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0263)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0263");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0263.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30642");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.51");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.52");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.53");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.54");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.55");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-403.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-405.html");
  script_xref(name:"URL", value:"https://xenbits.xen.org/xsa/advisory-406.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, kmod-virtualbox, kmod-xtables-addons' package(s) announced via the MGASA-2022-0263 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel update is based on upstream 5.15.55 and fixes at least the
following security issues:

There are use-after-free vulnerabilities caused by timer handler in
net/rose/rose_timer.c of linux that allow attackers to crash linux kernel
without any privileges (CVE-2022-2318).

Xen Block and Network PV device frontends don't zero memory regions before
sharing them with the backend (CVE-2022-26365, CVE-2022-33740, XSA-403).
Additionally the granularity of the grant table doesn't allow sharing less
than a 4K page, leading to unrelated data residing in the same 4K page as
data shared with a backend being accessible by such backend (CVE-2022-33741,
CVE-2022-33742, XSA-403).

Xen network backend may cause Linux netfront to use freed SKBs While adding
logic to support XDP (eXpress Data Path), a code label was moved in a way
allowing for SKBs having references (pointers) retained for further
processing to nevertheless be freed (CVE-2022-33743, XSA-405).

Xen Arm guests can cause Dom0 DoS via PV devices When mapping pages of guests
on Arm, dom0 is using an rbtree to keep track of the foreign mappings.
Updating of that rbtree is not always done completely with the related lock
held, resulting in a small race window, which can be used by unprivileged
guests via PV devices to cause inconsistencies of the rbtree. These
in consistencies can lead to Denial of Service (DoS) of dom0, e.g. by
causing crashes or the inability to perform further mappings of other guests
memory pages (CVE-2022-33744, XSA-406).

An issue was discovered in the Linux kernel through 5.18.9. A type confusion
bug in nft_set_elem_init (leading to a buffer overflow) could be used by a
local attacker to escalate privileges (The attacker can obtain root access,
but must start with an unprivileged user namespace to obtain CAP_NET_ADMIN
access) (CVE-2022-34918).

Other fixes in this update:
- ALSA: hda: Add fixup for Dell Latitidue E5430
- ALSA: hda/conexant: Apply quirk for another HP ProDesk 600 G3 model
- ALSA: hda/realtek: Enable the headset-mic on a Xiaomi laptop
- ALSA: hda/realtek: Fix headset mic for Acer SF313-51
- ALSA: hda/realtek: Fix headset mic problem for a HP machine with alc221
- ALSA: hda/realtek: Fix headset mic problem for a HP machine with alc671
- ALSA: hda/realtek: fix mute/micmute LEDs for HP ProBook 440/450 G9 and
 EliteBook 640/650 G9
- ARM: 9213/1: Print message about disabled Spectre workarounds only once
- net: sock: tracing: Fix sock_exceed_buf_limit not to dereference stale
 pointer (fixes crash)
- xen/netback: avoid entering xenvif_rx_next_skb() with an empty rx queue
 (fixes crash)
- xfs: only run COW extent recovery when there are no live extents
- xfs: don't include bnobt blocks when reserving free block pool
- xfs: run callbacks before waking waiters in xlog_state_shutdown_callbacks
- xfs: drop async cache flushes from CIL commits

For other upstream fixes, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel, kmod-virtualbox, kmod-xtables-addons' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.15.55~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower", rpm:"cpupower~5.15.55~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower-devel", rpm:"cpupower-devel~5.15.55~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.15.55~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-5.15.55-2.mga8", rpm:"kernel-desktop-5.15.55-2.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-5.15.55-2.mga8", rpm:"kernel-desktop-devel-5.15.55-2.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~5.15.55~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~5.15.55~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-5.15.55-2.mga8", rpm:"kernel-desktop586-5.15.55-2.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-5.15.55-2.mga8", rpm:"kernel-desktop586-devel-5.15.55-2.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~5.15.55~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~5.15.55~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~5.15.55~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-5.15.55-2.mga8", rpm:"kernel-server-5.15.55-2.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-5.15.55-2.mga8", rpm:"kernel-server-devel-5.15.55-2.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~5.15.55~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~5.15.55~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-5.15.55-2.mga8", rpm:"kernel-source-5.15.55-2.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~5.15.55~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~5.15.55~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~6.1.34~1.25.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~3.20~1.25.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf-devel", rpm:"lib64bpf-devel~5.15.55~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bpf0", rpm:"lib64bpf0~5.15.55~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf-devel", rpm:"libbpf-devel~5.15.55~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbpf0", rpm:"libbpf0~5.15.55~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~5.15.55~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.15.55-desktop-2.mga8", rpm:"virtualbox-kernel-5.15.55-desktop-2.mga8~6.1.34~1.25.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-5.15.55-server-2.mga8", rpm:"virtualbox-kernel-5.15.55-server-2.mga8~6.1.34~1.25.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~6.1.34~1.25.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~6.1.34~1.25.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.15.55-desktop-2.mga8", rpm:"xtables-addons-kernel-5.15.55-desktop-2.mga8~3.20~1.25.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.15.55-desktop586-2.mga8", rpm:"xtables-addons-kernel-5.15.55-desktop586-2.mga8~3.20~1.25.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-5.15.55-server-2.mga8", rpm:"xtables-addons-kernel-5.15.55-server-2.mga8~3.20~1.25.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop-latest", rpm:"xtables-addons-kernel-desktop-latest~3.20~1.25.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop586-latest", rpm:"xtables-addons-kernel-desktop586-latest~3.20~1.25.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-server-latest", rpm:"xtables-addons-kernel-server-latest~3.20~1.25.mga8", rls:"MAGEIA8"))) {
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
