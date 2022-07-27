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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0364");
  script_cve_id("CVE-2016-4578", "CVE-2016-5195", "CVE-2016-5243", "CVE-2016-5244", "CVE-2016-5400", "CVE-2016-6480", "CVE-2016-6828", "CVE-2016-7039");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-17 16:15:00 +0000 (Mon, 17 Feb 2020)");

  script_name("Mageia: Security Advisory (MGASA-2016-0364)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0364");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0364.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19639");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.17");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.18");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.19");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.20");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.21");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.22");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.23");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.24");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.25");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.26");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-tmb' package(s) announced via the MGASA-2016-0364 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update is based on the upstream 4.4.26 kernel and fixes at least
these security issues:

sound/core/timer.c in the Linux kernel through 4.6 does not initialize
certain r1 data structures, which allows local users to obtain sensitive
information from kernel stack memory via crafted use of the ALSA timer
interface, related to the (1) snd_timer_user_ccallback and (2)
snd_timer_user_tinterrupt functions (CVE-2016-4578).

A race condition was found in the way the Linux kernel's memory subsystem
handled the copy-on-write (COW) breakage of private read-only memory
mappings. An unprivileged local user could use this flaw to gain write
access to otherwise read-only memory mappings and thus increase their
privileges on the system. This could be abused by an attacker to modify
existing setuid files with instructions to elevate privileges. An exploit
using this technique has been found in the wild (CVE-2016-5195).

The tipc_nl_compat_link_dump function in net/tipc/netlink_compat.c in the
Linux kernel through 4.6.3 does not properly copy a certain string, which
allows local users to obtain sensitive information from kernel stack
memory by reading a Netlink message (CVE-2016-5243).

The rds_inc_info_copy function in net/rds/recv.c in the Linux kernel
through 4.6.3 does not initialize a certain structure member, which
allows remote attackers to obtain sensitive information from kernel
stack memory by reading an RDS message (CVE-2016-5244).

Memory leak in the airspy_probe function in
drivers/media/usb/airspy/airspy.c in the airspy USB driver in the Linux
kernel before 4.7 allows local users to cause a denial of service (memory
consumption) via a crafted USB device that emulates many VFL_TYPE_SDR or
VFL_TYPE_SUBDEV devices and performs many connect and disconnect
operations (CVE-2016-5400).

Race condition in the ioctl_send_fib function in
drivers/scsi/aacraid/commctrl.c in the Linux kernel through 4.7 allows
local users to cause a denial of service (out-of-bounds access or system
crash) by changing a certain size value, aka a 'double fetch'
vulnerability (CVE-2016-6480).

Marco Grassi discovered a use-after-free condition could occur in the TCP
retransmit queue handling code in the Linux kernel. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2016-6828)

Vladimir Bene discovered an unbounded recursion in the VLAN and TEB
Generic Receive Offload (GRO) processing implementations in the Linux
kernel, A remote attacker could use this to cause a stack corruption,
leading to a denial of service (system crash). (CVE-2016-7039)

This update also changes the following:
- enables STRICT_DEVMEM as a security hardening
- disables FW_LOADER_USER_HELPER_FALLBACK again (un-intentionally
enabled in 4.4 series upgrade) that slows down boot or even makes
wireless connection fail with drivers with multiple possible
firmwares (mga#19390).

For other fixes in this update, see the referenced changelogs.");

  script_tag(name:"affected", value:"'kernel-tmb' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb", rpm:"kernel-tmb~4.4.26~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-4.4.26-1.mga5", rpm:"kernel-tmb-desktop-4.4.26-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-4.4.26-1.mga5", rpm:"kernel-tmb-desktop-devel-4.4.26-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-latest", rpm:"kernel-tmb-desktop-devel-latest~4.4.26~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-latest", rpm:"kernel-tmb-desktop-latest~4.4.26~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-4.4.26-1.mga5", rpm:"kernel-tmb-source-4.4.26-1.mga5~1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-latest", rpm:"kernel-tmb-source-latest~4.4.26~1.mga5", rls:"MAGEIA5"))) {
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
