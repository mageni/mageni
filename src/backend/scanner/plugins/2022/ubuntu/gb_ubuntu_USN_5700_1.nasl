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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5700.1");
  script_cve_id("CVE-2022-2602", "CVE-2022-41674", "CVE-2022-42719", "CVE-2022-42720", "CVE-2022-42721", "CVE-2022-42722");
  script_tag(name:"creation_date", value:"2022-10-27 04:28:34 +0000 (Thu, 27 Oct 2022)");
  script_version("2022-10-27T10:11:07+0000");
  script_tag(name:"last_modification", value:"2022-10-27 10:11:07 +0000 (Thu, 27 Oct 2022)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-18 14:06:00 +0000 (Tue, 18 Oct 2022)");

  script_name("Ubuntu: Security Advisory (USN-5700-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.10");

  script_xref(name:"Advisory-ID", value:"USN-5700-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5700-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-gcp, linux-ibm, linux-kvm, linux-lowlatency, linux-oracle, linux-raspi' package(s) announced via the USN-5700-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"David Bouman and Billy Jheng Bing Jhong discovered that a race condition
existed in the io_uring subsystem in the Linux kernel, leading to a use-
after-free vulnerability. A local attacker could use this to cause a denial
of service (system crash) or possibly execute arbitrary code.
(CVE-2022-2602)

Sonke Huster discovered that an integer overflow vulnerability existed in
the WiFi driver stack in the Linux kernel, leading to a buffer overflow. A
physically proximate attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2022-41674)

Sonke Huster discovered that a use-after-free vulnerability existed in the
WiFi driver stack in the Linux kernel. A physically proximate attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2022-42719)

Sonke Huster discovered that the WiFi driver stack in the Linux kernel did
not properly perform reference counting in some situations, leading to a
use-after-free vulnerability. A physically proximate attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2022-42720)

Sonke Huster discovered that the WiFi driver stack in the Linux kernel did
not properly handle BSSID/SSID lists in some situations. A physically
proximate attacker could use this to cause a denial of service (infinite
loop). (CVE-2022-42721)

Sonke Huster discovered that the WiFi driver stack in the Linux kernel
contained a NULL pointer dereference vulnerability in certain situations. A
physically proximate attacker could use this to cause a denial of service
(system crash). (CVE-2022-42722)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-gcp, linux-ibm, linux-kvm, linux-lowlatency, linux-oracle, linux-raspi' package(s) on Ubuntu 22.10.");

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

if(release == "UBUNTU22.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1006-raspi-nolpae", ver:"5.19.0-1006.13", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1006-raspi", ver:"5.19.0-1006.13", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1009-lowlatency-64k", ver:"5.19.0-1009.10", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1009-lowlatency", ver:"5.19.0-1009.10", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1010-azure", ver:"5.19.0-1010.11", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1010-gcp", ver:"5.19.0-1010.11", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1010-ibm", ver:"5.19.0-1010.11", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1010-kvm", ver:"5.19.0-1010.11", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1010-oracle", ver:"5.19.0-1010.11", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-1011-aws", ver:"5.19.0-1011.12", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-23-generic-64k", ver:"5.19.0-23.24", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-23-generic-lpae", ver:"5.19.0-23.24", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.19.0-23-generic", ver:"5.19.0-23.24", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"5.19.0.1011.10", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"5.19.0.1010.9", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"5.19.0.1010.9", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k", ver:"5.19.0.23.22", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"5.19.0.23.22", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"5.19.0.23.22", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-ibm", ver:"5.19.0.1010.9", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"5.19.0.1010.9", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k", ver:"5.19.0.1009.8", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"5.19.0.1009.8", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oem-22.04", ver:"5.19.0.23.22", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"5.19.0.1010.9", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-nolpae", ver:"5.19.0.1006.7", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"5.19.0.1006.7", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"5.19.0.23.22", rls:"UBUNTU22.10"))) {
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
