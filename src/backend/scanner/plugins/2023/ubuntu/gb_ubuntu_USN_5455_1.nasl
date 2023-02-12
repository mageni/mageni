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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5455.1");
  script_cve_id("CVE-2012-1148", "CVE-2015-1283", "CVE-2016-0718", "CVE-2016-4472", "CVE-2018-20843", "CVE-2019-15903", "CVE-2021-46143", "CVE-2022-22822", "CVE-2022-22823", "CVE-2022-22824", "CVE-2022-22825", "CVE-2022-22826", "CVE-2022-22827", "CVE-2022-25235", "CVE-2022-25236");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-23 20:55:00 +0000 (Wed, 23 Feb 2022)");

  script_name("Ubuntu: Security Advisory (USN-5455-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5455-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5455-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxmltok' package(s) announced via the USN-5455-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tim Boddy, Gustavo Grieco and others discovered that Expat, that is
integrated in xmltok library, incorrectly handled certain files.
An attacker could possibly use these issues to cause a denial of
service, or possibly execute arbitrary code. These issues were only
addressed in Ubuntu 16.04 ESM. (CVE-2012-1148, CVE-2015-1283,
CVE-2016-0718, CVE-2016-4472, CVE-2018-20843, CVE-2019-15903,
CVE-2021-46143, CVE-2022-22822, CVE-2022-22823, CVE-2022-22824,
CVE-2022-22825, CVE-2022-22826, CVE-2022-22827)

It was discovered that Expat, that is integrated in xmltok library,
incorrectly handled encoding validation of certain files. An attacker
could possibly use this issue to cause a denial of service, or
possibly execute arbitrary code. (CVE-2022-25235)

It was discovered that Expat, that is integrated in xmltok library,
incorrectly handled namespace URIs of certain files. An attacker
could possibly use this issue to cause a denial of service, or
possibly execute arbitrary code. (CVE-2022-25236)");

  script_tag(name:"affected", value:"'libxmltok' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libxmltok1", ver:"1.2-3ubuntu0.16.04.1~esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libxmltok1", ver:"1.2-4ubuntu0.18.04.1~esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libxmltok1", ver:"1.2-4ubuntu0.20.04.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libxmltok1", ver:"1.2-4ubuntu0.22.04.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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
