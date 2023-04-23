# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0149");
  script_cve_id("CVE-2022-4269", "CVE-2022-4379", "CVE-2023-1076", "CVE-2023-1077", "CVE-2023-1079", "CVE-2023-1118", "CVE-2023-1611", "CVE-2023-1670", "CVE-2023-1829", "CVE-2023-1855", "CVE-2023-1989", "CVE-2023-1990", "CVE-2023-25012", "CVE-2023-28466", "CVE-2023-30456", "CVE-2023-30772");
  script_tag(name:"creation_date", value:"2023-04-18 04:13:05 +0000 (Tue, 18 Apr 2023)");
  script_version("2023-04-18T10:10:05+0000");
  script_tag(name:"last_modification", value:"2023-04-18 10:10:05 +0000 (Tue, 18 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-13 20:10:00 +0000 (Thu, 13 Apr 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0149)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0149");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0149.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31778");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.99");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.100");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.101");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.102");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.103");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.104");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.105");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v5.x/ChangeLog-5.15.106");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-linus' package(s) announced via the MGASA-2023-0149 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-linus update is based on upstream 5.15.106 and fixes at least the
following security issues:

A flaw was found in the Linux Kernel. The tun/tap sockets have their socket
UID hardcoded to 0 due to a type confusion in their initialization function.
While it will be often correct, as tuntap devices require CAP_NET_ADMIN,
it may not always be the case, e.g., a non-root user only having that
capability. This would make tun/tap sockets being incorrectly treated in
filtering/routing decisions, possibly bypassing network filters
(CVE-2023-1076).

In the Linux kernel, pick_next_rt_entity() may return a type confused entry,
not detected by the BUG_ON condition, as the confused entry will not be
NULL, but list_head.The buggy error condition would lead to a type confused
entry with the list head,which would then be used as a type confused
sched_rt_entity,causing memory corruption (CVE-2023-1077).

A flaw was found in the Linux kernel. A use-after-free may be triggered in
asus_kbd_backlight_set when plugging/disconnecting in a malicious USB device,
which advertises itself as an Asus device. Similarly to the previous known
CVE-2023-25012, but in asus devices, the work_struct may be scheduled by the
LED controller while the device is disconnecting, triggering a use-after-free
on the struct asus_kbd_leds *led structure. A malicious USB device may
exploit the issue to cause memory corruption with controlled data
(CVE-2023-1079).

A flaw use after free in the Linux kernel integrated infrared receiver/
transceiver driver was found in the way user detaching rc device. A local
user could use this flaw to crash the system or potentially escalate their
privileges on the system (CVE-2023-1118).

A use-after-free flaw was found in btrfs_search_slot in fs/btrfs/ctree.c
in btrfs in the Linux Kernel.This flaw allows an attacker to crash the
system and possibly cause a kernel information leak (CVE-2023-1611).

A flaw use after free in the Linux kernel Xircom 16-bit PCMCIA (PC-card)
Ethernet driver was found.A local user could use this flaw to crash the
system or potentially escalate their privileges on the system
(CVE-2023-1670).

A use-after-free vulnerability in the Linux Kernel traffic control index
filter (tcindex) can be exploited to achieve local privilege escalation.
The tcindex_delete function which does not properly deactivate filters in
case of a perfect hashes while deleting the underlying structure which can
later lead to double freeing the structure. A local attacker user can use
this vulnerability to elevate its privileges to root (CVE-2023-1829).

A use-after-free flaw was found in xgene_hwmon_remove in drivers/hwmon/
xgene-hwmon.c in the Hardware Monitoring Linux Kernel Driver (xgene-hwmon).
This flaw could allow a local attacker to crash the system due to a race
problem. This vulnerability could even lead to a kernel information leak
problem (CVE-2023-1855).

A ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-5.15.106-1.mga8", rpm:"kernel-linus-5.15.106-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus", rpm:"kernel-linus~5.15.106~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-5.15.106-1.mga8", rpm:"kernel-linus-devel-5.15.106-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-devel-latest", rpm:"kernel-linus-devel-latest~5.15.106~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-doc", rpm:"kernel-linus-doc~5.15.106~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-latest", rpm:"kernel-linus-latest~5.15.106~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-5.15.106-1.mga8", rpm:"kernel-linus-source-5.15.106-1.mga8~1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-linus-source-latest", rpm:"kernel-linus-source-latest~5.15.106~1.mga8", rls:"MAGEIA8"))) {
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
