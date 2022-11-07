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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5708.1");
  script_cve_id("CVE-2022-41674", "CVE-2022-42719", "CVE-2022-42720", "CVE-2022-42721", "CVE-2022-42722");
  script_tag(name:"creation_date", value:"2022-11-02 04:34:55 +0000 (Wed, 02 Nov 2022)");
  script_version("2022-11-02T10:12:00+0000");
  script_tag(name:"last_modification", value:"2022-11-02 10:12:00 +0000 (Wed, 02 Nov 2022)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-18 14:06:00 +0000 (Tue, 18 Oct 2022)");

  script_name("Ubuntu: Security Advisory (USN-5708-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|22\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5708-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5708-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1994525");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'backport-iwlwifi-dkms' package(s) announced via the USN-5708-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sonke Huster discovered that an integer overflow vulnerability existed in
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
(system crash). This issue only affected Ubuntu 20.04 LTS and Ubuntu 22.10.
(CVE-2022-42722)");

  script_tag(name:"affected", value:"'backport-iwlwifi-dkms' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 22.10.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"backport-iwlwifi-dkms", ver:"8324-0ubuntu3~20.04.5", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"backport-iwlwifi-dkms", ver:"9858-0ubuntu3.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"backport-iwlwifi-dkms", ver:"9904-0ubuntu3.1", rls:"UBUNTU22.10"))) {
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
