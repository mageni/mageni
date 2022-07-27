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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0472");
  script_cve_id("CVE-2016-0801", "CVE-2017-0561", "CVE-2017-13080", "CVE-2017-13081", "CVE-2017-9417");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-08 16:06:00 +0000 (Fri, 08 Mar 2019)");

  script_name("Mageia: Security Advisory (MGASA-2017-0472)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0472");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0472.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22100");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-firmware-nonfree, radeon-firmware' package(s) announced via the MGASA-2017-0472 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated nonfree firmwares fixes at least the following security issues:

Broadcom firmware fixes:
- dropping BRCM proprietary packets received over the air (CVE-2016-0801)
- adding length checks for TDLS action frames (CVE-2017-0561)
- adding length checks for WME IE (CVE-2017-9417)

Iwlwifi firmware fixes:
- The reinstallation of the Group Temporal key could be used for replay
 attacks (CVE-2017-13080)
- The reinstallation of the Integrity Group Temporal key could be used
 for replay attacks (CVE-2017-13081)

This update also adds updated firmwares:
* ath10k, cxgb4, liquidio, mrvl, ql2400, ql2500, wilc1000
* Amd Polaris10-12, Intel BXT/SKL/KBL/CNL

and new firmwares:
* Amd Vega10 and Raven
* Cavium nitrox
* Intel CNL/GLK, IPU3, JeffersonPeak, ThunderPeak
* Mellanox Spectrum
* nVidia GP108 (GTX1030)
* Qualcom Adreno &Venus, imx SDMA,
* Realtek rtl8822be

in order to support new hardware supported by 4.14 series kernels.");

  script_tag(name:"affected", value:"'kernel-firmware-nonfree, radeon-firmware' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"iwlwifi-firmware", rpm:"iwlwifi-firmware~20171220~1.mga6.nonfree", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nonfree", rpm:"kernel-firmware-nonfree~20171220~1.mga6.nonfree", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radeon-firmware", rpm:"radeon-firmware~20171205~1.mga6.nonfree", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ralink-firmware", rpm:"ralink-firmware~20171220~1.mga6.nonfree", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rtlwifi-firmware", rpm:"rtlwifi-firmware~20171220~1.mga6.nonfree", rls:"MAGEIA6"))) {
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
