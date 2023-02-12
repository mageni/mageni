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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5620.1");
  script_cve_id("CVE-2021-20296", "CVE-2021-23215", "CVE-2021-26260", "CVE-2021-3598", "CVE-2021-3605", "CVE-2021-3933", "CVE-2021-3941");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-04 16:45:00 +0000 (Mon, 04 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-5620-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5620-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5620-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openexr' package(s) announced via the USN-5620-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenEXR incorrectly handled certain malformed EXR
image files. If a user were tricked into opening a crafted EXR image file,
a remote attacker could cause a denial of service, or possibly execute
arbitrary code. These issues only affected Ubuntu 20.04 ESM. (CVE-2021-3598,
CVE-2021-3605, CVE-2021-20296, CVE-2021-23215, CVE-2021-26260)

It was discovered that OpenEXR incorrectly handled certain EXR
image files. An attacker could possibly use this issue to cause a crash
or execute arbitrary code. (CVE-2021-3933)

It was discovered that OpenEXR incorrectly handled certain EXR image files.
An attacker could possibly use this issue to cause a crash. (CVE-2021-3941)");

  script_tag(name:"affected", value:"'openexr' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libopenexr24", ver:"2.3.0-6ubuntu0.5+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openexr", ver:"2.3.0-6ubuntu0.5+esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libopenexr25", ver:"2.5.7-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openexr", ver:"2.5.7-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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
