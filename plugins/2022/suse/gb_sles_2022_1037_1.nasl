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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1037.1");
  script_cve_id("CVE-2021-0920", "CVE-2021-39657", "CVE-2021-44879", "CVE-2022-0487", "CVE-2022-0617", "CVE-2022-0644", "CVE-2022-24448", "CVE-2022-24958", "CVE-2022-24959", "CVE-2022-25258", "CVE-2022-25636", "CVE-2022-26490");
  script_tag(name:"creation_date", value:"2022-03-31 04:11:26 +0000 (Thu, 31 Mar 2022)");
  script_version("2022-03-31T04:11:26+0000");
  script_tag(name:"last_modification", value:"2022-03-31 10:53:41 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-17 19:28:00 +0000 (Thu, 17 Feb 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1037-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1037-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221037-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:1037-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2022-25636: Fixed an issue which allowed a local users to gain
 privileges because of a heap out-of-bounds write in nf_dup_netdev.c,
 related to nf_tables_offload (bsc#1196299).

CVE-2022-26490: Fixed a buffer overflow in the st21nfca driver. An
 attacker with adjacent NFC access could trigger crash the system or
 corrupt system memory (bsc#1196830).

CVE-2022-0487: A use-after-free vulnerability was found in
 rtsx_usb_ms_drv_remove() in drivers/memstick/host/rtsx_usb_ms.c
 (bsc#1194516).

CVE-2022-24448: Fixed an issue if an application sets the O_DIRECTORY
 flag, and tries to open a regular file, nfs_atomic_open() performs a
 regular lookup. If a regular file is found, ENOTDIR should have occurred,
 but the server instead returned uninitialized data in the file
 descriptor (bsc#1195612).

CVE-2022-0617: Fixed a null pointer dereference in UDF file system
 functionality. A local user could crash the system by triggering
 udf_file_write_iter() via a malicious UDF image. (bsc#1196079)

CVE-2022-0644: Fixed a denial of service by a local user. A assertion
 failure could be triggered in kernel_read_file_from_fd(). (bsc#1196155)

CVE-2022-25258: The USB Gadget subsystem lacked certain validation of
 interface OS descriptor requests, which could have lead to memory
 corruption (bsc#1196096).

CVE-2022-24958: drivers/usb/gadget/legacy/inode.c mishandled dev->buf
 release (bsc#1195905).

CVE-2022-24959: Fixed a memory leak in yam_siocdevprivate() in
 drivers/net/hamradio/yam.c (bsc#1195897).

CVE-2021-44879: In gc_data_segment() in fs/f2fs/gc.c, special files were
 not considered, which lead to a move_data_page NULL pointer dereference
 (bsc#1195987).

CVE-2021-0920: Fixed a local privilege escalation due to a
 use-after-free vulnerability in unix_scm_to_skb of af_unix (bsc#1193731).

CVE-2021-39657: Fixed an information leak in the Universal Flash Storage
 subsystem (bsc#1193864).

The following non-security bugs were fixed:

ALSA: intel_hdmi: Fix reference to PCM buffer address (git-fixes).

ARM: 9182/1: mmu: fix returns from early_param() and __setup() functions
 (git-fixes).

ARM: Fix kgdb breakpoint for Thumb2 (git-fixes).

ASoC: cs4265: Fix the duplicated control name (git-fixes).

ASoC: ops: Shift tested values in snd_soc_put_volsw() by +min
 (git-fixes).

ASoC: rt5668: do not block workqueue if card is unbound (git-fixes).

ASoC: rt5682: do not block workqueue if card is unbound (git-fixes).

Bluetooth: btusb: Add missing Chicony device for Realtek RTL8723BE
 (bsc#1196779).

EDAC/altera: Fix deferred probing (bsc#1178134).

HID: add mapping for KEY_ALL_APPLICATIONS (git-fixes).

HID: add mapping for KEY_DICTATE (git-fixes).

Hand over the maintainership to SLE15-SP3 maintainers

IB/hfi1: Correct guard on eager buffer deallocation ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~150300.38.50.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~150300.38.50.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~150300.38.50.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~150300.38.50.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~150300.38.50.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~150300.38.50.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~150300.38.50.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~150300.38.50.1", rls:"SLES15.0SP3"))) {
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
