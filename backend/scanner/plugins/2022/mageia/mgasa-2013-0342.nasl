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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0342");
  script_cve_id("CVE-2013-2015", "CVE-2013-2888", "CVE-2013-2889", "CVE-2013-2892", "CVE-2013-2893", "CVE-2013-2895", "CVE-2013-2896", "CVE-2013-2897", "CVE-2013-2899", "CVE-2013-4162", "CVE-2013-4163", "CVE-2013-4254", "CVE-2013-4348", "CVE-2013-4350", "CVE-2013-4387", "CVE-2013-4470", "CVE-2013-4483");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-03-06 04:47:00 +0000 (Thu, 06 Mar 2014)");

  script_name("Mageia: Security Advisory (MGASA-2013-0342)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA2");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0342");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0342.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11468");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.53");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.54");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.55");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.56");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.57");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.58");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.59");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.60");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.61");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.62");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.63");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.64");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.65");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.66");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.67");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.68");
  script_xref(name:"URL", value:"https://www.kernel.org/pub/linux/kernel/v3.x/ChangeLog-3.4.69");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, kernel-userspace-headers, kmod-broadcom-wl, kmod-fglrx, kmod-nvidia-current, kmod-nvidia173, kmod-nvidia96xx, kmod-vboxadditions, kmod-virtualbox, kmod-xtables-addons' package(s) announced via the MGASA-2013-0342 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel update provides the upstream 3.4.69 kernel and fixes the
following security issues:

The ext4_orphan_del function in fs/ext4/namei.c in the Linux kernel before
3.7.3 does not properly handle orphan-list entries for non-journal
filesystems, which allows physically proximate attackers to cause a denial
of service (system hang) via a crafted filesystem on removable media, as
demonstrated by the e2fsprogs tests/f_orphan_extents_inode/image.gz test
(CVE-2013-2015).

Multiple array index errors in drivers/hid/hid-core.c in the Human
Interface Device (HID) subsystem in the Linux kernel through 3.11 allow
physically proximate attackers to execute arbitrary code or cause a
denial of service (heap memory corruption) via a crafted device that
provides an invalid Report ID (CVE-2013-2888).

drivers/hid/hid-zpff.c in the Human Interface Device (HID) subsystem
in the Linux kernel through 3.11, when CONFIG_HID_ZEROPLUS is enabled,
allows physically proximate attackers to cause a denial of service
(heap-based out-of-bounds write) via a crafted device (CVE-2013-2889).

drivers/hid/hid-pl.c in the Human Interface Device (HID) subsystem in
the Linux kernel through 3.11, when CONFIG_HID_PANTHERLORD is enabled,
allows physically proximate attackers to cause a denial of service
(heap-based out-of-bounds write) via a crafted device (CVE-2013-2892).

The Human Interface Device (HID) subsystem in the Linux kernel
through 3.11, when CONFIG_LOGITECH_FF, CONFIG_LOGIG940_FF, or
CONFIG_LOGIWHEELS_FF is enabled, allows physically proximate
attackers to cause a denial of service (heap-based out-of-bounds
write) via a crafted device, related to (1) drivers/hid/hid-lgff.c,
(2) drivers/hid/hid-lg3ff.c, and (3) drivers/hid/hid-lg4ff.c
(CVE-2013-2893).

drivers/hid/hid-logitech-dj.c in the Human Interface Device (HID)
subsystem in the Linux kernel through 3.11, when CONFIG_HID_LOGITECH_DJ
is enabled, allows physically proximate attackers to cause a denial
of service (NULL pointer dereference and OOPS) or obtain sensitive
information from kernel memory via a crafted device (CVE-2013-2895).

drivers/hid/hid-ntrig.c in the Human Interface Device (HID)
subsystem in the Linux kernel through 3.11, when CONFIG_HID_NTRIG
is enabled, allows physically proximate attackers to cause a denial
of service (NULL pointer dereference and OOPS) via a crafted device
(CVE-2013-2896).

Multiple array index errors in drivers/hid/hid-multitouch.c in the
Human Interface Device (HID) subsystem in the Linux kernel through
3.11, when CONFIG_HID_MULTITOUCH is enabled, allow physically proximate
attackers to cause a denial of service (heap memory corruption, or NULL
pointer dereference and OOPS) via a crafted device (CVE-2013-2897).

drivers/hid/hid-picolcd_core.c in the Human Interface Device (HID)
subsystem in the Linux kernel through 3.11, when CONFIG_HID_PICOLCD
is enabled, allows physically proximate attackers to cause ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel, kernel-userspace-headers, kmod-broadcom-wl, kmod-fglrx, kmod-nvidia-current, kmod-nvidia173, kmod-nvidia96xx, kmod-vboxadditions, kmod-virtualbox, kmod-xtables-addons' package(s) on Mageia 2.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-3.4.69-desktop-1.mga2", rpm:"broadcom-wl-kernel-3.4.69-desktop-1.mga2~5.100.82.112~52.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-3.4.69-desktop586-1.mga2", rpm:"broadcom-wl-kernel-3.4.69-desktop586-1.mga2~5.100.82.112~52.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-3.4.69-netbook-1.mga2", rpm:"broadcom-wl-kernel-3.4.69-netbook-1.mga2~5.100.82.112~52.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-3.4.69-server-1.mga2", rpm:"broadcom-wl-kernel-3.4.69-server-1.mga2~5.100.82.112~52.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-desktop-latest", rpm:"broadcom-wl-kernel-desktop-latest~5.100.82.112~52.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-desktop586-latest", rpm:"broadcom-wl-kernel-desktop586-latest~5.100.82.112~52.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-netbook-latest", rpm:"broadcom-wl-kernel-netbook-latest~5.100.82.112~52.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"broadcom-wl-kernel-server-latest", rpm:"broadcom-wl-kernel-server-latest~5.100.82.112~52.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower", rpm:"cpupower~3.4.69~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpupower-devel", rpm:"cpupower-devel~3.4.69~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-3.4.69-desktop-1.mga2", rpm:"fglrx-kernel-3.4.69-desktop-1.mga2~8.961~28.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-3.4.69-desktop586-1.mga2", rpm:"fglrx-kernel-3.4.69-desktop586-1.mga2~8.961~28.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-3.4.69-netbook-1.mga2", rpm:"fglrx-kernel-3.4.69-netbook-1.mga2~8.961~28.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-3.4.69-server-1.mga2", rpm:"fglrx-kernel-3.4.69-server-1.mga2~8.961~28.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-desktop-latest", rpm:"fglrx-kernel-desktop-latest~8.961~28.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-desktop586-latest", rpm:"fglrx-kernel-desktop586-latest~8.961~28.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-netbook-latest", rpm:"fglrx-kernel-netbook-latest~8.961~28.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fglrx-kernel-server-latest", rpm:"fglrx-kernel-server-latest~8.961~28.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.4.69~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-3.4.69-1.mga2", rpm:"kernel-desktop-3.4.69-1.mga2~1~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-3.4.69-1.mga2", rpm:"kernel-desktop-devel-3.4.69-1.mga2~1~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~3.4.69~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~3.4.69~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-3.4.69-1.mga2", rpm:"kernel-desktop586-3.4.69-1.mga2~1~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-3.4.69-1.mga2", rpm:"kernel-desktop586-devel-3.4.69-1.mga2~1~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~3.4.69~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~3.4.69~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.4.69~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-netbook-3.4.69-1.mga2", rpm:"kernel-netbook-3.4.69-1.mga2~1~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-netbook-devel-3.4.69-1.mga2", rpm:"kernel-netbook-devel-3.4.69-1.mga2~1~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-netbook-devel-latest", rpm:"kernel-netbook-devel-latest~3.4.69~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-netbook-latest", rpm:"kernel-netbook-latest~3.4.69~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-3.4.69-1.mga2", rpm:"kernel-server-3.4.69-1.mga2~1~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-3.4.69-1.mga2", rpm:"kernel-server-devel-3.4.69-1.mga2~1~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~3.4.69~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~3.4.69~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-3.4.69-1.mga2", rpm:"kernel-source-3.4.69-1.mga2~1~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~3.4.69~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-userspace-headers", rpm:"kernel-userspace-headers~3.4.69~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-broadcom-wl", rpm:"kmod-broadcom-wl~5.100.82.112~52.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-fglrx", rpm:"kmod-fglrx~8.961~28.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-nvidia-current", rpm:"kmod-nvidia-current~295.71~23.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-nvidia173", rpm:"kmod-nvidia173~173.14.36~18.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-nvidia96xx", rpm:"kmod-nvidia96xx~96.43.23~19.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-vboxadditions", rpm:"kmod-vboxadditions~4.2.16~5.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-virtualbox", rpm:"kmod-virtualbox~4.2.16~5.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-xtables-addons", rpm:"kmod-xtables-addons~1.41~33.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-3.4.69-desktop-1.mga2", rpm:"nvidia-current-kernel-3.4.69-desktop-1.mga2~295.71~23.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-3.4.69-desktop586-1.mga2", rpm:"nvidia-current-kernel-3.4.69-desktop586-1.mga2~295.71~23.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-3.4.69-netbook-1.mga2", rpm:"nvidia-current-kernel-3.4.69-netbook-1.mga2~295.71~23.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-3.4.69-server-1.mga2", rpm:"nvidia-current-kernel-3.4.69-server-1.mga2~295.71~23.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-desktop-latest", rpm:"nvidia-current-kernel-desktop-latest~295.71~23.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-desktop586-latest", rpm:"nvidia-current-kernel-desktop586-latest~295.71~23.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-netbook-latest", rpm:"nvidia-current-kernel-netbook-latest~295.71~23.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-current-kernel-server-latest", rpm:"nvidia-current-kernel-server-latest~295.71~23.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-3.4.69-desktop-1.mga2", rpm:"nvidia173-kernel-3.4.69-desktop-1.mga2~173.14.36~18.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-3.4.69-desktop586-1.mga2", rpm:"nvidia173-kernel-3.4.69-desktop586-1.mga2~173.14.36~18.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-3.4.69-netbook-1.mga2", rpm:"nvidia173-kernel-3.4.69-netbook-1.mga2~173.14.36~18.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-3.4.69-server-1.mga2", rpm:"nvidia173-kernel-3.4.69-server-1.mga2~173.14.36~18.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-desktop-latest", rpm:"nvidia173-kernel-desktop-latest~173.14.36~18.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-desktop586-latest", rpm:"nvidia173-kernel-desktop586-latest~173.14.36~18.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-netbook-latest", rpm:"nvidia173-kernel-netbook-latest~173.14.36~18.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia173-kernel-server-latest", rpm:"nvidia173-kernel-server-latest~173.14.36~18.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia96xx-kernel-3.4.69-desktop-1.mga2", rpm:"nvidia96xx-kernel-3.4.69-desktop-1.mga2~96.43.23~19.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia96xx-kernel-3.4.69-desktop586-1.mga2", rpm:"nvidia96xx-kernel-3.4.69-desktop586-1.mga2~96.43.23~19.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia96xx-kernel-3.4.69-netbook-1.mga2", rpm:"nvidia96xx-kernel-3.4.69-netbook-1.mga2~96.43.23~19.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia96xx-kernel-3.4.69-server-1.mga2", rpm:"nvidia96xx-kernel-3.4.69-server-1.mga2~96.43.23~19.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia96xx-kernel-desktop-latest", rpm:"nvidia96xx-kernel-desktop-latest~96.43.23~19.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia96xx-kernel-desktop586-latest", rpm:"nvidia96xx-kernel-desktop586-latest~96.43.23~19.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia96xx-kernel-netbook-latest", rpm:"nvidia96xx-kernel-netbook-latest~96.43.23~19.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia96xx-kernel-server-latest", rpm:"nvidia96xx-kernel-server-latest~96.43.23~19.mga2.nonfree", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.4.69~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-3.4.69-desktop-1.mga2", rpm:"vboxadditions-kernel-3.4.69-desktop-1.mga2~4.2.16~5.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-3.4.69-desktop586-1.mga2", rpm:"vboxadditions-kernel-3.4.69-desktop586-1.mga2~4.2.16~5.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-3.4.69-netbook-1.mga2", rpm:"vboxadditions-kernel-3.4.69-netbook-1.mga2~4.2.16~5.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-3.4.69-server-1.mga2", rpm:"vboxadditions-kernel-3.4.69-server-1.mga2~4.2.16~5.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop-latest", rpm:"vboxadditions-kernel-desktop-latest~4.2.16~5.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-desktop586-latest", rpm:"vboxadditions-kernel-desktop586-latest~4.2.16~5.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-netbook-latest", rpm:"vboxadditions-kernel-netbook-latest~4.2.16~5.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vboxadditions-kernel-server-latest", rpm:"vboxadditions-kernel-server-latest~4.2.16~5.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-3.4.69-desktop-1.mga2", rpm:"virtualbox-kernel-3.4.69-desktop-1.mga2~4.2.16~5.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-3.4.69-desktop586-1.mga2", rpm:"virtualbox-kernel-3.4.69-desktop586-1.mga2~4.2.16~5.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-3.4.69-netbook-1.mga2", rpm:"virtualbox-kernel-3.4.69-netbook-1.mga2~4.2.16~5.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-3.4.69-server-1.mga2", rpm:"virtualbox-kernel-3.4.69-server-1.mga2~4.2.16~5.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~4.2.16~5.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~4.2.16~5.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-netbook-latest", rpm:"virtualbox-kernel-netbook-latest~4.2.16~5.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~4.2.16~5.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-3.4.69-desktop-1.mga2", rpm:"xtables-addons-kernel-3.4.69-desktop-1.mga2~1.41~33.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-3.4.69-desktop586-1.mga2", rpm:"xtables-addons-kernel-3.4.69-desktop586-1.mga2~1.41~33.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-3.4.69-netbook-1.mga2", rpm:"xtables-addons-kernel-3.4.69-netbook-1.mga2~1.41~33.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-3.4.69-server-1.mga2", rpm:"xtables-addons-kernel-3.4.69-server-1.mga2~1.41~33.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop-latest", rpm:"xtables-addons-kernel-desktop-latest~1.41~33.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-desktop586-latest", rpm:"xtables-addons-kernel-desktop586-latest~1.41~33.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-netbook-latest", rpm:"xtables-addons-kernel-netbook-latest~1.41~33.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xtables-addons-kernel-server-latest", rpm:"xtables-addons-kernel-server-latest~1.41~33.mga2", rls:"MAGEIA2"))) {
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
