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
  script_oid("1.3.6.1.4.1.25623.1.0.854728");
  script_version("2022-06-15T04:37:18+0000");
  script_cve_id("CVE-2021-26312", "CVE-2021-26339", "CVE-2021-26342", "CVE-2021-26347", "CVE-2021-26348", "CVE-2021-26349", "CVE-2021-26350", "CVE-2021-26364", "CVE-2021-26372", "CVE-2021-26373", "CVE-2021-26375", "CVE-2021-26376", "CVE-2021-26378", "CVE-2021-26388", "CVE-2021-33139", "CVE-2021-33155", "CVE-2021-46744");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-06-15 10:13:29 +0000 (Wed, 15 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-03 01:01:54 +0000 (Fri, 03 Jun 2022)");
  script_name("openSUSE: Security Advisory for kernel-firmware (SUSE-SU-2022:1923-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1923-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4VJQBTBCWDRPAVJ62BTMK5TJWKWFW6CK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-firmware'
  package(s) announced via the SUSE-SU-2022:1923-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kernel-firmware fixes the following issues:
  Update to version 20220411 (git commit f219d616f42b, bsc#1199459):

  - CVE-2021-26373, CVE-2021-26347, CVE-2021-26376, CVE-2021-26350,
       CVE-2021-26375, CVE-2021-26378, CVE-2021-26372, CVE-2021-26339,
       CVE-2021-26348, CVE-2021-26342, CVE-2021-26388, CVE-2021-26349,
       CVE-2021-26364, CVE-2021-26312: Update AMD cpu microcode
  Update to version 20220309 (git commit cd01f857da28, bsc#1199470):

  - CVE-2021-46744: Ciphertext Side Channels on AMD SEV
  Update Intel Bluetooth firmware (INTEL-SA-00604, bsc#1195786):

  - CVE-2021-33139, CVE-2021-33155: Improper conditions check in the
       firmware for some Intel Wireless Bluetooth and Killer Bluetooth products
       may allow an authenticated user to potentially cause denial of service
       via adjacent access.
  Special Instructions and Notes:
  Please reboot the system after installing this update.");

  script_tag(name:"affected", value:"'kernel-firmware' package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-20220509", rpm:"kernel-firmware-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-all-20220509", rpm:"kernel-firmware-all-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-amdgpu-20220509", rpm:"kernel-firmware-amdgpu-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath10k-20220509", rpm:"kernel-firmware-ath10k-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath11k-20220509", rpm:"kernel-firmware-ath11k-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-atheros-20220509", rpm:"kernel-firmware-atheros-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-bluetooth-20220509", rpm:"kernel-firmware-bluetooth-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-bnx2-20220509", rpm:"kernel-firmware-bnx2-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-brcm-20220509", rpm:"kernel-firmware-brcm-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-chelsio-20220509", rpm:"kernel-firmware-chelsio-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-dpaa2-20220509", rpm:"kernel-firmware-dpaa2-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-i915-20220509", rpm:"kernel-firmware-i915-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-intel-20220509", rpm:"kernel-firmware-intel-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-iwlwifi-20220509", rpm:"kernel-firmware-iwlwifi-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-liquidio-20220509", rpm:"kernel-firmware-liquidio-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-marvell-20220509", rpm:"kernel-firmware-marvell-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-media-20220509", rpm:"kernel-firmware-media-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mediatek-20220509", rpm:"kernel-firmware-mediatek-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mellanox-20220509", rpm:"kernel-firmware-mellanox-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mwifiex-20220509", rpm:"kernel-firmware-mwifiex-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-network-20220509", rpm:"kernel-firmware-network-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nfp-20220509", rpm:"kernel-firmware-nfp-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nvidia-20220509", rpm:"kernel-firmware-nvidia-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-platform-20220509", rpm:"kernel-firmware-platform-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-prestera-20220509", rpm:"kernel-firmware-prestera-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-qcom-20220509", rpm:"kernel-firmware-qcom-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-qlogic-20220509", rpm:"kernel-firmware-qlogic-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-radeon-20220509", rpm:"kernel-firmware-radeon-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-realtek-20220509", rpm:"kernel-firmware-realtek-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-serial-20220509", rpm:"kernel-firmware-serial-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-sound-20220509", rpm:"kernel-firmware-sound-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ti-20220509", rpm:"kernel-firmware-ti-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ueagle-20220509", rpm:"kernel-firmware-ueagle-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-usb-network-20220509", rpm:"kernel-firmware-usb-network-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-amd-20220509", rpm:"ucode-amd-20220509~150400.4.5.1", rls:"openSUSELeap15.4"))) {
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