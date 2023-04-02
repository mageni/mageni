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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5974.1");
  script_cve_id("CVE-2018-20184", "CVE-2018-20189", "CVE-2018-5685", "CVE-2018-9018", "CVE-2019-11006", "CVE-2020-12672", "CVE-2022-1270");
  script_tag(name:"creation_date", value:"2023-03-28 00:20:39 +0000 (Tue, 28 Mar 2023)");
  script_version("2023-03-28T10:09:39+0000");
  script_tag(name:"last_modification", value:"2023-03-28 10:09:39 +0000 (Tue, 28 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-5974-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5974-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5974-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'graphicsmagick' package(s) announced via the USN-5974-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that GraphicsMagick was not properly performing bounds
checks when processing TGA image files, which could lead to a heap buffer
overflow. If a user or automated system were tricked into processing a
specially crafted TGA image file, an attacker could possibly use this
issue to cause a denial of service or execute arbitrary code. This issue
only affected Ubuntu 14.04 ESM and Ubuntu 16.04 ESM. (CVE-2018-20184)

It was discovered that GraphicsMagick was not properly validating bits per
pixel data when processing DIB image files. If a user or automated system
were tricked into processing a specially crafted DIB image file, an
attacker could possibly use this issue to cause a denial of service. This
issue only affected Ubuntu 14.04 ESM and Ubuntu 16.04 ESM.
(CVE-2018-20189)

It was discovered that GraphicsMagick was not properly processing
bit-field mask values in BMP image files, which could result in the
execution of an infinite loop. If a user or automated system were tricked
into processing a specially crafted BMP image file, an attacker could
possibly use this issue to cause a denial of service. This issue only
affected Ubuntu 14.04 ESM and Ubuntu 16.04 ESM. (CVE-2018-5685)

It was discovered that GraphicsMagick was not properly validating data
used in arithmetic operations when processing MNG image files, which
could result in a divide-by-zero error. If a user or automated system were
tricked into processing a specially crafted MNG image file, an attacker
could possibly use this issue to cause a denial of service. This issue
only affected Ubuntu 14.04 ESM and Ubuntu 16.04 ESM. (CVE-2018-9018)

It was discovered that GraphicsMagick was not properly performing bounds
checks when processing MIFF image files, which could lead to a heap buffer
overflow. If a user or automated system were tricked into processing a
specially crafted MIFF image file, an attacker could possibly use this
issue to cause a denial of service or expose sensitive information. This
issue only affected Ubuntu 14.04 ESM and Ubuntu 16.04 ESM.
(CVE-2019-11006)

It was discovered that GraphicsMagick did not properly magnify certain
MNG image files, which could lead to a heap buffer overflow. If a user or
automated system were tricked into processing a specially crafted MNG
image file, an attacker could possibly use this issue to cause a denial
of service or execute arbitrary code. This issue only affected Ubuntu
20.04 LTS. (CVE-2020-12672)

It was discovered that GraphicsMagick was not properly performing bounds
checks when parsing certain MIFF image files, which could lead to a heap
buffer overflow. If a user or automated system were tricked into
processing a specially crafted MIFF image file, an attacker could possibly
use this issue to cause a denial of service or execute arbitrary code.
(CVE-2022-1270)");

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

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick", ver:"1.3.18-1ubuntu3.1+esm8", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick3", ver:"1.3.18-1ubuntu3.1+esm8", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick", ver:"1.3.23-1ubuntu0.6+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick-q16-3", ver:"1.3.23-1ubuntu0.6+esm2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick", ver:"1.3.28-2ubuntu0.2+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick-q16-3", ver:"1.3.28-2ubuntu0.2+esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"graphicsmagick", ver:"1.4+really1.3.35-1ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgraphicsmagick-q16-3", ver:"1.4+really1.3.35-1ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
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
