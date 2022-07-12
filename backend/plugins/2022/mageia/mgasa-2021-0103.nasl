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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0103");
  script_cve_id("CVE-2019-15126");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"2.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-11 19:15:00 +0000 (Tue, 11 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2021-0103)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0103");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0103.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28475");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-firmware-nonfree, radeon-firmware' package(s) announced via the MGASA-2021-0103 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated nonfree firmwares fixees various issues, adds new / improved
hardware support and fixes at least the following security issue:

An issue was discovered on Broadcom Wi-Fi client devices. Specifically
timed and handcrafted traffic can cause internal errors (related to
state transitions) in a WLAN device that lead to improper layer 2
Wi-Fi encryption with a consequent possibility of information
disclosure over the air for a discrete set of traffic (CVE-2019-15126).

Full list of updates:
* kernel-firmware-nonfree:
 - add firmware for Lontium LT9611UXC DSI to HDMI bridge
 - brcm: Add NVRAM for Vamrs 96boards Rock960
 - brcm: make AP6212 in bananpi m2 plus/zero work
 - brcm: Link RPi4's WiFi firmware with DMI machine name
 - brcm: Update Raspberry Pi 3B+/4B NVRAM for downstream changes
 - brcm: remove old brcm firmwares that have newer cypress variants
 (CVE-2019-15126)
 - cypress: Link the new cypress firmware to the old brcm files
 (CVE-2019-15126)
 - i915: Add GuC firmware v49.0.1 for all platforms
 - i915: Add GuC v49.0.1 for DG1
 - i915: Add HuC v7.7.1 for DG1
 - i915: Add DMC v2.01 for ADL-S
 - mediatek: update MT8173 VPU firmware to v1.1.6
 - mediatek: add firmware for MT7921
 - Mellanox: Add new mlxsw_spectrum firmware xx.2008.2304
 - QCA : Updated firmware files for WCN3991
 - qcom: add firmware files for Adreno a650
 - qcom: Add SM8250 Audio DSP firmware
 - qcom: Add SM8250 Compute DSP firmware
 - qcom: Add venus firmware files for VPU-1.0

* iwlwifi-firmware:
 - Update firmware for Intel Bluetooth 9260, 9560 to 22.20.0.3
 - Update firmware for Intel Bluetooth AX200, AX201, AX210 to 22.30.0.4

* rtlwifi-firmware:
 - rtl_bt: Update RTL8821C BT(USB I/F) FW to 0x829a_7644
 - rtl_bt: Update RTL8822C BT(USB I/F) FW to 0x099a_7253
 - rtl_bt: Update RTL8822C BT(UART I/F) FW to 0x059A_25CB
 - rtl_bt: Add firmware and config files for RTL8852A BT USB chip
 - rtw88: RTL8821C: Update firmware to v24.8 (for rfe type 2 support)
 - rtw88: RTL8822C: Update normal firmware to v9.9.5 (performance fixes)
 - rtw89: 8852a: add firmware v0.9.12.2

* radeon-firmware:
 - amdgpu: add initial firmware for green sardine");

  script_tag(name:"affected", value:"'kernel-firmware-nonfree, radeon-firmware' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"iwlwifi-firmware", rpm:"iwlwifi-firmware~20210223~1.mga7.nonfree", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nonfree", rpm:"kernel-firmware-nonfree~20210223~1.mga7.nonfree", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radeon-firmware", rpm:"radeon-firmware~20210211~1.mga7.nonfree", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ralink-firmware", rpm:"ralink-firmware~20210223~1.mga7.nonfree", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rtlwifi-firmware", rpm:"rtlwifi-firmware~20210223~1.mga7.nonfree", rls:"MAGEIA7"))) {
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
