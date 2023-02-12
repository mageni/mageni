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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0146.1");
  script_cve_id("CVE-2022-3104", "CVE-2022-3105", "CVE-2022-3106", "CVE-2022-3107", "CVE-2022-3108", "CVE-2022-3111", "CVE-2022-3112", "CVE-2022-3113", "CVE-2022-3114", "CVE-2022-3115", "CVE-2022-3344", "CVE-2022-3564", "CVE-2022-4379", "CVE-2022-4662", "CVE-2022-47520");
  script_tag(name:"creation_date", value:"2023-01-27 04:21:47 +0000 (Fri, 27 Jan 2023)");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-14 04:36:00 +0000 (Sat, 14 Jan 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0146-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0146-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230146-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:0146-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2022-3344: Fixed a flaw found in the KVM's AMD nested virtualization
 (SVM). A malicious L1 guest could purposely fail to intercept the
 shutdown of a cooperative nested guest (L2), possibly leading to a page
 fault and kernel panic in the host (L0). (bsc#1204652)

CVE-2022-4662: Fixed a recursive locking violation in usb-storage that
 can cause the kernel to deadlock. (bsc#1206664)

CVE-2022-3115: Fixed a null pointer dereference in malidp_crtc.c caused
 by a lack of checks of the return value of kzalloc. (bsc#1206393)

CVE-2022-47520: Fixed an out-of-bounds read when parsing a Robust
 Security Network (RSN) information element from a Netlink packet.
 (bsc#1206515)

CVE-2022-3112: Fixed a null pointer dereference caused by a missing
 check of the return value of kzalloc() in
 vdec_helpers.c:amvdec_set_canvases. (bsc#1206399)

CVE-2022-3564: Fixed a bug which could lead to use after free, it was
 found in the function l2cap_reassemble_sdu of the file
 net/bluetooth/l2cap_core.c of the component Bluetooth. (bsc#1206073)

CVE-2022-4379: Fixed a use-after-free vulnerability in
 nfs4file.c:__nfs42_ssc_open. (bsc#1206209)

CVE-2022-3108: Fixed a bug in kfd_parse_subtype_iolink in
 drivers/gpu/drm/amd/amdkfd/kfd_crat.c where a lack of check of the
 return value of kmemdup() could lead to a NULL pointer dereference.
 (bsc#1206389)

CVE-2022-3104: Fixed a null pointer dereference caused by caused by a
 missing check of the return value of kzalloc() in
 bugs.c:lkdtm_ARRAY_BOUNDS. (bsc#1206396)

CVE-2022-3113: Fixed a null pointer dereference caused by a missing
 check of the return value of devm_kzalloc. (bsc#1206390)

CVE-2022-3107: Fixed a null pointer dereference caused by a missing
 check of the return value of kvmalloc_array. (bsc#1206395)

CVE-2022-3114: Fixed a null pointer dereference caused by a missing
 check of the return value of kcalloc. (bsc#1206391)

CVE-2022-3111: Fixed a missing release of resource after effective
 lifetime bug caused by a missing free of the WM8350_IRQ_CHG_FAST_RDY in
 wm8350_init_charger. (bsc#1206394)

CVE-2022-3105: Fixed a null pointer dereference caused by a missing
 check of the return value of kmalloc_array. (bsc#1206398)

CVE-2022-3106: Fixed a null pointer dereference caused by a missing
 check of the return value of kmalloc. (bsc#1206397)

The following non-security bugs were fixed:

acct: fix potential integer overflow in encode_comp_t() (git-fixes).

ACPI: resource: Skip IRQ override on Asus Vivobook K3402ZA/K3502ZA
 (git-fixes).

ACPICA: Fix error code path in acpi_ds_call_control_method() (git-fixes).

ACPICA: Fix use-after-free in acpi_ut_copy_ipackage_to_ipackage()
 (git-fixes).

ALSA: asihpi: fix missing pci_disable_device() (git-fixes).

ALSA: hda/hdmi: Add HP Device 0x8711 to force connect ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.14.21~150400.14.31.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.14.21~150400.14.31.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.14.21~150400.14.31.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.14.21~150400.14.31.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.14.21~150400.14.31.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.14.21~150400.14.31.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.14.21~150400.14.31.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.14.21~150400.14.31.1", rls:"SLES15.0SP4"))) {
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
