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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5764.1");
  script_cve_id("CVE-2022-2347", "CVE-2022-30552", "CVE-2022-30767", "CVE-2022-30790", "CVE-2022-33103", "CVE-2022-33967", "CVE-2022-34835");
  script_tag(name:"creation_date", value:"2022-12-07 04:10:10 +0000 (Wed, 07 Dec 2022)");
  script_version("2022-12-07T10:11:17+0000");
  script_tag(name:"last_modification", value:"2022-12-07 10:11:17 +0000 (Wed, 07 Dec 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-09 02:28:00 +0000 (Sat, 09 Jul 2022)");

  script_name("Ubuntu: Security Advisory (USN-5764-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|22\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5764-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5764-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'u-boot' package(s) announced via the USN-5764-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that U-Boot incorrectly handled certain USB DFU download
setup packets. A local attacker could use this issue to cause U-Boot to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2022-2347)

Nicolas Bidron and Nicolas Guigo discovered that U-Boot incorrectly handled
certain fragmented IP packets. A local attacker could use this issue to
cause U-Boot to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 18.04 LTS, Ubuntu
20.04 LTS, and Ubuntu 22.04 LTS. (CVE-2022-30552, CVE-2022-30790)

It was discovered that U-Boot incorrectly handled certain NFS lookup
replies. A remote attacker could use this issue to cause U-Boot to crash,
resulting in a denial of service, or possibly execute arbitrary code. This
issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 22.04
LTS. (CVE-2022-30767)

Jincheng Wang discovered that U-Boot incorrectly handled certain SquashFS
structures. A local attacker could use this issue to cause U-Boot to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and
Ubuntu 22.04 LTS. (CVE-2022-33103)

Tatsuhiko Yasumatsu discovered that U-Boot incorrectly handled certain
SquashFS structures. A local attacker could use this issue to cause U-Boot
to crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and
Ubuntu 22.04 LTS. (CVE-2022-33967)

It was discovered that U-Boot incorrectly handled the i2c command. A local
attacker could use this issue to cause U-Boot to crash, resulting in a
denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, and Ubuntu 22.04 LTS.
(CVE-2022-34835)");

  script_tag(name:"affected", value:"'u-boot' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 22.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-amlogic", ver:"2020.10+dfsg-1ubuntu0~18.04.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-exynos", ver:"2020.10+dfsg-1ubuntu0~18.04.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-imx", ver:"2020.10+dfsg-1ubuntu0~18.04.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-mvebu", ver:"2020.10+dfsg-1ubuntu0~18.04.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-omap", ver:"2020.10+dfsg-1ubuntu0~18.04.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-qcom", ver:"2020.10+dfsg-1ubuntu0~18.04.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-qemu", ver:"2020.10+dfsg-1ubuntu0~18.04.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-rockchip", ver:"2020.10+dfsg-1ubuntu0~18.04.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-rpi", ver:"2020.10+dfsg-1ubuntu0~18.04.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-sunxi", ver:"2020.10+dfsg-1ubuntu0~18.04.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-tegra", ver:"2020.10+dfsg-1ubuntu0~18.04.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-tools", ver:"2020.10+dfsg-1ubuntu0~18.04.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot", ver:"2020.10+dfsg-1ubuntu0~18.04.3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-amlogic", ver:"2021.01+dfsg-3ubuntu0~20.04.5", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-exynos", ver:"2021.01+dfsg-3ubuntu0~20.04.5", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-imx", ver:"2021.01+dfsg-3ubuntu0~20.04.5", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-mvebu", ver:"2021.01+dfsg-3ubuntu0~20.04.5", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-omap", ver:"2021.01+dfsg-3ubuntu0~20.04.5", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-qcom", ver:"2021.01+dfsg-3ubuntu0~20.04.5", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-qemu", ver:"2021.01+dfsg-3ubuntu0~20.04.5", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-rockchip", ver:"2021.01+dfsg-3ubuntu0~20.04.5", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-rpi", ver:"2021.01+dfsg-3ubuntu0~20.04.5", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-sifive", ver:"2021.01+dfsg-3ubuntu0~20.04.5", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-sunxi", ver:"2021.01+dfsg-3ubuntu0~20.04.5", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-tegra", ver:"2021.01+dfsg-3ubuntu0~20.04.5", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-tools", ver:"2021.01+dfsg-3ubuntu0~20.04.5", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot", ver:"2021.01+dfsg-3ubuntu0~20.04.5", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-amlogic", ver:"2022.01+dfsg-2ubuntu2.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-exynos", ver:"2022.01+dfsg-2ubuntu2.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-imx", ver:"2022.01+dfsg-2ubuntu2.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-microchip", ver:"2022.01+dfsg-2ubuntu2.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-mvebu", ver:"2022.01+dfsg-2ubuntu2.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-omap", ver:"2022.01+dfsg-2ubuntu2.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-qcom", ver:"2022.01+dfsg-2ubuntu2.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-qemu", ver:"2022.01+dfsg-2ubuntu2.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-rockchip", ver:"2022.01+dfsg-2ubuntu2.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-rpi", ver:"2022.01+dfsg-2ubuntu2.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-sifive", ver:"2022.01+dfsg-2ubuntu2.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-sunxi", ver:"2022.01+dfsg-2ubuntu2.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-tegra", ver:"2022.01+dfsg-2ubuntu2.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-tools", ver:"2022.01+dfsg-2ubuntu2.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot", ver:"2022.01+dfsg-2ubuntu2.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.10") {

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-amlogic", ver:"2022.07+dfsg-1ubuntu4.2", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-exynos", ver:"2022.07+dfsg-1ubuntu4.2", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-imx", ver:"2022.07+dfsg-1ubuntu4.2", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-microchip", ver:"2022.07+dfsg-1ubuntu4.2", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-mvebu", ver:"2022.07+dfsg-1ubuntu4.2", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-omap", ver:"2022.07+dfsg-1ubuntu4.2", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-qcom", ver:"2022.07+dfsg-1ubuntu4.2", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-qemu", ver:"2022.07+dfsg-1ubuntu4.2", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-rockchip", ver:"2022.07+dfsg-1ubuntu4.2", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-rpi", ver:"2022.07+dfsg-1ubuntu4.2", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-sifive", ver:"2022.07+dfsg-1ubuntu4.2", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-stm32", ver:"2022.07+dfsg-1ubuntu4.2", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-sunxi", ver:"2022.07+dfsg-1ubuntu4.2", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-tegra", ver:"2022.07+dfsg-1ubuntu4.2", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot-tools", ver:"2022.07+dfsg-1ubuntu4.2", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"u-boot", ver:"2022.07+dfsg-1ubuntu4.2", rls:"UBUNTU22.10"))) {
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
