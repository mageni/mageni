# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853616");
  script_version("2021-04-21T07:29:02+0000");
  script_cve_id("CVE-2020-14372", "CVE-2020-25632", "CVE-2020-25647", "CVE-2020-27749", "CVE-2020-27779", "CVE-2021-20225", "CVE-2021-20233");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-04-21 10:10:24 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 04:56:57 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for grub2 (openSUSE-SU-2021:0462-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0462-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XXPYL42MSKRB4D7LRFMW7PBGGLKSJKPS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grub2'
  package(s) announced via the openSUSE-SU-2021:0462-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for grub2 fixes the following issues:

     grub2 implements the new 'SBAT' method for SHIM based secure boot
     revocation. (bsc#1182057)

  - CVE-2020-25632: Fixed a use-after-free in rmmod command (bsc#1176711)

  - CVE-2020-25647: Fixed an out-of-bound write in
       grub_usb_device_initialize() (bsc#1177883)

  - CVE-2020-27749: Fixed a stack buffer overflow in
       grub_parser_split_cmdline (bsc#1179264)

  - CVE-2020-27779, CVE-2020-14372: Disallow cutmem and acpi commands in
       secure boot mode (bsc#1179265 bsc#1175970)

  - CVE-2021-20225: Fixed a heap out-of-bounds write in short form option
       parser (bsc#1182262)

  - CVE-2021-20233: Fixed a heap out-of-bound write due to mis-calculation
       of space required for quoting (bsc#1182263)

  - Fixed chainloading windows on dual boot machine (bsc#1183073)

     This update was imported from the SUSE:SLE-15-SP2:Update update project.");

  script_tag(name:"affected", value:"'grub2' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"grub2", rpm:"grub2~2.04~lp152.7.22.7", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-branding-upstream", rpm:"grub2-branding-upstream~2.04~lp152.7.22.7", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-debuginfo", rpm:"grub2-debuginfo~2.04~lp152.7.22.7", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-debugsource", rpm:"grub2-debugsource~2.04~lp152.7.22.7", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-i386-efi", rpm:"grub2-i386-efi~2.04~lp152.7.22.7", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-i386-efi-debug", rpm:"grub2-i386-efi-debug~2.04~lp152.7.22.7", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-i386-pc", rpm:"grub2-i386-pc~2.04~lp152.7.22.7", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-i386-pc-debug", rpm:"grub2-i386-pc-debug~2.04~lp152.7.22.7", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-i386-xen", rpm:"grub2-i386-xen~2.04~lp152.7.22.7", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-snapper-plugin", rpm:"grub2-snapper-plugin~2.04~lp152.7.22.7", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-systemd-sleep-plugin", rpm:"grub2-systemd-sleep-plugin~2.04~lp152.7.22.7", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-x86_64-efi", rpm:"grub2-x86_64-efi~2.04~lp152.7.22.7", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-x86_64-efi-debug", rpm:"grub2-x86_64-efi-debug~2.04~lp152.7.22.7", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-x86_64-xen", rpm:"grub2-x86_64-xen~2.04~lp152.7.22.7", rls:"openSUSELeap15.2"))) {
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