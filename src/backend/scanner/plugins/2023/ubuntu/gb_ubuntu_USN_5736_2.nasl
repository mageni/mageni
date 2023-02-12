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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5736.2");
  script_cve_id("CVE-2021-20224", "CVE-2021-20241", "CVE-2021-20243", "CVE-2021-20244", "CVE-2021-20245", "CVE-2021-20246", "CVE-2021-20309", "CVE-2021-20312", "CVE-2021-20313", "CVE-2021-3574", "CVE-2021-39212", "CVE-2021-4219", "CVE-2022-1114", "CVE-2022-28463", "CVE-2022-32545", "CVE-2022-32546", "CVE-2022-32547");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-30 18:14:00 +0000 (Thu, 30 Jun 2022)");

  script_name("Ubuntu: Security Advisory (USN-5736-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5736-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5736-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'imagemagick' package(s) announced via the USN-5736-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5736-1 fixed vulnerabilities in ImageMagick. This update provides the
corresponding updates for Ubuntu 20.04 ESM and Ubuntu 22.04 ESM. One of the
issues, CVE-2021-20224, only affected Ubuntu 20.04 ESM, while
CVE-2021-20245, CVE-2021-3574, CVE-2021-4219 and CVE-2022-1114 only
affected Ubuntu 22.04 ESM.

Original advisory details:

 It was discovered that ImageMagick incorrectly handled certain values
 when processing PDF files. If a user or automated system using ImageMagick
 were tricked into opening a specially crafted PDF file, an attacker could
 exploit this to cause a denial of service. This issue only affected Ubuntu
 14.04 ESM, Ubuntu 16.04 ESM and Ubuntu 18.04 LTS. (CVE-2021-20224)

 Zhang Xiaohui discovered that ImageMagick incorrectly handled certain
 values when processing image data. If a user or automated system using
 ImageMagick were tricked into opening a specially crafted image, an
 attacker could exploit this to cause a denial of service. This issue only
 affected Ubuntu 18.04 LTS and Ubuntu 22.10. (CVE-2021-20241)

 Zhang Xiaohui discovered that ImageMagick incorrectly handled certain
 values when processing image data. If a user or automated system using
 ImageMagick were tricked into opening a specially crafted image, an
 attacker could exploit this to cause a denial of service. This issue only
 affected Ubuntu 14.04 ESM, Ubuntu 18.04 LTS and Ubuntu 22.10.
 (CVE-2021-20243)

 It was discovered that ImageMagick incorrectly handled certain values
 when processing visual effects based image files. By tricking a user into
 opening a specially crafted image file, an attacker could crash the
 application causing a denial of service. This issue only affected Ubuntu
 22.10. (CVE-2021-20244)

 It was discovered that ImageMagick could be made to divide by zero when
 processing crafted files. By tricking a user into opening a specially
 crafted image file, an attacker could crash the application causing a
 denial of service. This issue only affected Ubuntu 22.10. (CVE-2021-20245)

 It was discovered that ImageMagick incorrectly handled certain values
 when performing resampling operations. By tricking a user into opening
 a specially crafted image file, an attacker could crash the application
 causing a denial of service. This issue only affected Ubuntu 22.10.
 (CVE-2021-20246)

 It was discovered that ImageMagick incorrectly handled certain values
 when processing visual effects based image files. By tricking a user into
 opening a specially crafted image file, an attacker could crash the
 application causing a denial of service. This issue only affected Ubuntu
 22.10. (CVE-2021-20309)

 It was discovered that ImageMagick incorrectly handled certain values
 when processing thumbnail image data. By tricking a user into opening
 a specially crafted image file, an attacker could crash the application
 causing a denial of service. This issue only affected ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6-common", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.4+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6.q16", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.4+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6.q16hdri", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.4+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-common", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.4+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.4+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-perl", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.4+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-q16-perl", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.4+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16-8", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.4+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16-dev", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.4+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16hdri-8", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.4+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-dev", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.4+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6-arch-config", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.4+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6-headers", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.4+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-6-extra", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.4+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-6", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.4+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-dev", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.4+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16hdri-6", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.4+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-dev", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.4+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6-headers", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.4+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16-6", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.4+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16-dev", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.4+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-dev", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.4+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perlmagick", ver:"8:6.9.10.23+dfsg-2.1ubuntu11.4+esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6-common", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6.q16", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-6.q16hdri", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick-common", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-perl", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libimage-magick-q16-perl", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16-8", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16-dev", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-6.q16hdri-8", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++-dev", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6-arch-config", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6-headers", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-6-extra", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-6", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16-dev", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-6.q16hdri-6", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickcore-dev", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16-6", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-6.q16-dev", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagickwand-dev", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perlmagick", ver:"8:6.9.11.60+dfsg-1.3ubuntu0.22.04.1+esm1", rls:"UBUNTU22.04 LTS"))) {
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
