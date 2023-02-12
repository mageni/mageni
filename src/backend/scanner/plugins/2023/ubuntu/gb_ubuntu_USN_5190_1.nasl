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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5190.1");
  script_cve_id("CVE-2019-12921", "CVE-2019-19950", "CVE-2019-19951", "CVE-2019-19953", "CVE-2020-10938", "CVE-2020-12672");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-31 06:15:00 +0000 (Tue, 31 Mar 2020)");

  script_name("Ubuntu: Security Advisory (USN-5190-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5190-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5190-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'graphicsmagick' package(s) announced via the USN-5190-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that GraphicsMagick allowed reading arbitrary files via
specially crafted images. An attacker could use this issue to expose sensitive
information. This issue only affects Ubuntu 14.04 ESM, Ubuntu 16.04 ESM, and
Ubuntu 18.04 ESM. (CVE-2019-12921)

It was discovered that GraphicsMagick did not correctly handle memory
allocations for error messages. An attacker could use this issue to corrupt
memory or possibly execute arbitrary code. This issue only affects Ubuntu 14.04
ESM, Ubuntu 16.04 ESM, and Ubuntu 18.04 ESM. (CVE-2019-19950)

It was discovered that GraphicsMagick did not correctly handle type limits.
An attacker could use these issues to cause heap-based buffer overflows,
leading to a denial of service (application crash) or possibly execute
arbitrary code. These issues only affect Ubuntu 14.04 ESM, Ubuntu 16.04 ESM, and
Ubuntu 18.04 ESM. (CVE-2019-19951, CVE-2019-19953)

It was discovered that GraphicsMagick did not correctly handle the signed
integer limit in 32-bit applications. An attacker could use this issue to cause
a heap-based buffer overflow, leading to a denial of service (application crash)
or possibly execute arbitrary code. This issue only affects Ubuntu 14.04 ESM,
Ubuntu 16.04 ESM, and Ubuntu 18.04 ESM. (CVE-2020-10938)

It was discovered that GraphicsMagick did not properly magnify certain
images. An attacker could use this issue to cause a heap-based buffer
overflow, leading to a denial of service (application crash) or possibly
execute arbitrary code. (CVE-2020-12672)");

  script_tag(name:"affected", value:"'graphicsmagick' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick", ver:"1.3.18-1ubuntu3.1+esm7", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick++3", ver:"1.3.18-1ubuntu3.1+esm7", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick3", ver:"1.3.18-1ubuntu3.1+esm7", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick", ver:"1.3.23-1ubuntu0.6+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick++-q16-12", ver:"1.3.23-1ubuntu0.6+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick-q16-3", ver:"1.3.23-1ubuntu0.6+esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick", ver:"1.3.28-2ubuntu0.1+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick++-q16-12", ver:"1.3.28-2ubuntu0.1+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick-q16-3", ver:"1.3.28-2ubuntu0.1+esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick", ver:"1.4+really1.3.35-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick++-q16-12", ver:"1.4+really1.3.35-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick-q16-3", ver:"1.4+really1.3.35-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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
