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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1923.1");
  script_cve_id("CVE-2021-26312", "CVE-2021-26339", "CVE-2021-26342", "CVE-2021-26347", "CVE-2021-26348", "CVE-2021-26349", "CVE-2021-26350", "CVE-2021-26364", "CVE-2021-26372", "CVE-2021-26373", "CVE-2021-26375", "CVE-2021-26376", "CVE-2021-26378", "CVE-2021-26388", "CVE-2021-33139", "CVE-2021-33155", "CVE-2021-46744");
  script_tag(name:"creation_date", value:"2022-06-03 04:18:28 +0000 (Fri, 03 Jun 2022)");
  script_version("2022-06-03T04:18:28+0000");
  script_tag(name:"last_modification", value:"2022-06-07 09:57:21 +0000 (Tue, 07 Jun 2022)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-01 16:56:00 +0000 (Wed, 01 Jun 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1923-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1923-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221923-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-firmware' package(s) announced via the SUSE-SU-2022:1923-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kernel-firmware fixes the following issues:

Update to version 20220411 (git commit f219d616f42b, bsc#1199459):

CVE-2021-26373, CVE-2021-26347, CVE-2021-26376, CVE-2021-26350,
 CVE-2021-26375, CVE-2021-26378, CVE-2021-26372, CVE-2021-26339,
 CVE-2021-26348, CVE-2021-26342, CVE-2021-26388, CVE-2021-26349,
 CVE-2021-26364, CVE-2021-26312: Update AMD cpu microcode


Update to version 20220309 (git commit cd01f857da28, bsc#1199470):

CVE-2021-46744: Ciphertext Side Channels on AMD SEV


Update Intel Bluetooth firmware (INTEL-SA-00604, bsc#1195786):

CVE-2021-33139, CVE-2021-33155: Improper conditions check in the
 firmware for some Intel Wireless Bluetooth and Killer Bluetooth products
 may allow an authenticated user to potentially cause denial of service
 via adjacent access.");

  script_tag(name:"affected", value:"'kernel-firmware' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-all", rpm:"kernel-firmware-all~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-amdgpu", rpm:"kernel-firmware-amdgpu~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath10k", rpm:"kernel-firmware-ath10k~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath11k", rpm:"kernel-firmware-ath11k~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-atheros", rpm:"kernel-firmware-atheros~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-bluetooth", rpm:"kernel-firmware-bluetooth~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-bnx2", rpm:"kernel-firmware-bnx2~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-brcm", rpm:"kernel-firmware-brcm~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-chelsio", rpm:"kernel-firmware-chelsio~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-dpaa2", rpm:"kernel-firmware-dpaa2~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-i915", rpm:"kernel-firmware-i915~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-intel", rpm:"kernel-firmware-intel~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-iwlwifi", rpm:"kernel-firmware-iwlwifi~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-liquidio", rpm:"kernel-firmware-liquidio~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-marvell", rpm:"kernel-firmware-marvell~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-media", rpm:"kernel-firmware-media~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mediatek", rpm:"kernel-firmware-mediatek~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mellanox", rpm:"kernel-firmware-mellanox~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mwifiex", rpm:"kernel-firmware-mwifiex~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-network", rpm:"kernel-firmware-network~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nfp", rpm:"kernel-firmware-nfp~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nvidia", rpm:"kernel-firmware-nvidia~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-platform", rpm:"kernel-firmware-platform~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-prestera", rpm:"kernel-firmware-prestera~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-qcom", rpm:"kernel-firmware-qcom~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-qlogic", rpm:"kernel-firmware-qlogic~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-radeon", rpm:"kernel-firmware-radeon~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-realtek", rpm:"kernel-firmware-realtek~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-serial", rpm:"kernel-firmware-serial~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-sound", rpm:"kernel-firmware-sound~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ti", rpm:"kernel-firmware-ti~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ueagle", rpm:"kernel-firmware-ueagle~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-usb-network", rpm:"kernel-firmware-usb-network~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-amd", rpm:"ucode-amd~20220509~150400.4.5.1", rls:"SLES15.0SP4"))) {
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
