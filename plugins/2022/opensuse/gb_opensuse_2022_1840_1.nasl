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
  script_oid("1.3.6.1.4.1.25623.1.0.854704");
  script_version("2022-05-31T10:55:22+0000");
  script_cve_id("CVE-2021-26312", "CVE-2021-26339", "CVE-2021-26342", "CVE-2021-26347", "CVE-2021-26348", "CVE-2021-26349", "CVE-2021-26350", "CVE-2021-26364", "CVE-2021-26372", "CVE-2021-26373", "CVE-2021-26375", "CVE-2021-26376", "CVE-2021-26378", "CVE-2021-26388", "CVE-2021-46744");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-06-01 10:00:47 +0000 (Wed, 01 Jun 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-23 16:49:00 +0000 (Mon, 23 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-26 01:01:44 +0000 (Thu, 26 May 2022)");
  script_name("openSUSE: Security Advisory for kernel-firmware (SUSE-SU-2022:1840-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1840-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4BXZJPBMKANARAA3VO6JSVP3WW4VVBOD");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-firmware'
  package(s) announced via the SUSE-SU-2022:1840-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kernel-firmware fixes the following issues:
  Update AMD ucode and SEV firmware
     - (CVE-2021-26339, CVE-2021-26373, CVE-2021-26347, CVE-2021-26376,
       CVE-2021-26375, CVE-2021-26378, CVE-2021-26372, CVE-2021-26339,
       CVE-2021-26348, CVE-2021-26342, CVE-2021-26388, CVE-2021-26349,
       CVE-2021-26364, CVE-2021-26312, CVE-2021-26350, CVE-2021-46744,
       bsc#1199459, bsc#1199470)");

  script_tag(name:"affected", value:"'kernel-firmware' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-20210208", rpm:"kernel-firmware-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-all-20210208", rpm:"kernel-firmware-all-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-amdgpu-20210208", rpm:"kernel-firmware-amdgpu-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath10k-20210208", rpm:"kernel-firmware-ath10k-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath11k-20210208", rpm:"kernel-firmware-ath11k-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-atheros-20210208", rpm:"kernel-firmware-atheros-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-bluetooth-20210208", rpm:"kernel-firmware-bluetooth-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-bnx2-20210208", rpm:"kernel-firmware-bnx2-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-brcm-20210208", rpm:"kernel-firmware-brcm-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-chelsio-20210208", rpm:"kernel-firmware-chelsio-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-dpaa2-20210208", rpm:"kernel-firmware-dpaa2-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-i915-20210208", rpm:"kernel-firmware-i915-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-intel-20210208", rpm:"kernel-firmware-intel-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-iwlwifi-20210208", rpm:"kernel-firmware-iwlwifi-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-liquidio-20210208", rpm:"kernel-firmware-liquidio-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-marvell-20210208", rpm:"kernel-firmware-marvell-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-media-20210208", rpm:"kernel-firmware-media-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mediatek-20210208", rpm:"kernel-firmware-mediatek-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mellanox-20210208", rpm:"kernel-firmware-mellanox-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mwifiex-20210208", rpm:"kernel-firmware-mwifiex-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-network-20210208", rpm:"kernel-firmware-network-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nfp-20210208", rpm:"kernel-firmware-nfp-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nvidia-20210208", rpm:"kernel-firmware-nvidia-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-platform-20210208", rpm:"kernel-firmware-platform-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-prestera-20210208", rpm:"kernel-firmware-prestera-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-qlogic-20210208", rpm:"kernel-firmware-qlogic-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-radeon-20210208", rpm:"kernel-firmware-radeon-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-realtek-20210208", rpm:"kernel-firmware-realtek-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-serial-20210208", rpm:"kernel-firmware-serial-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-sound-20210208", rpm:"kernel-firmware-sound-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ti-20210208", rpm:"kernel-firmware-ti-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ueagle-20210208", rpm:"kernel-firmware-ueagle-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-usb-network-20210208", rpm:"kernel-firmware-usb-network-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-amd-20210208", rpm:"ucode-amd-20210208~150300.4.10.1", rls:"openSUSELeap15.3"))) {
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