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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.4818.1");
  script_cve_id("CVE-2017-18009", "CVE-2019-14491", "CVE-2019-14492", "CVE-2019-14493", "CVE-2019-15939");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-02 03:15:00 +0000 (Mon, 02 Dec 2019)");

  script_name("Ubuntu: Security Advisory (USN-4818-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4818-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4818-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opencv' package(s) announced via the USN-4818-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenCV did not properly manage certain
objects, leading to a divide-by-zero. If a user were tricked into
loading a specially crafted file, a remote attacker could potentially use
this issue to cause a denial of service or possibly execute arbitrary
code. (CVE-2019-15939)

It was discovered that OpenCV did not properly manage certain files,
leading to an out of bounds read. If a user were tricked into loading
a specially crafted file, a remote attacker could potentially use this
issue to make OpenCV crash, resulting in a denial of service. This issue
was only fixed in Ubuntu 18.04 ESM. (CVE-2019-14491, CVE-2019-14492)

It was discovered that OpenCV did not properly manage certain XML data,
leading to a NULL pointer dereference. If a user were tricked into
loading a specially crafted file, a remote attacker could potentially use
this issue to make OpenCV crash, resulting in a denial of service. This
issue was only fixed in Ubuntu 14.04 ESM and Ubuntu 16.04 ESM.
(CVE-2019-14493)

It was discovered that OpenCV did not properly manage certain files,
leading to a heap-based buffer overflow. If a user were tricked into
loading a specially crafted file, a remote attacker could potentially use
this issue to cause a denial of service or possibly execute arbitrary code.
This issue only affected Ubuntu 18.04 ESM. (CVE-2017-18009)");

  script_tag(name:"affected", value:"'opencv' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-calib3d2.4", ver:"2.4.8+dfsg1-2ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-contrib2.4", ver:"2.4.8+dfsg1-2ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-core2.4", ver:"2.4.8+dfsg1-2ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-features2d2.4", ver:"2.4.8+dfsg1-2ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-flann2.4", ver:"2.4.8+dfsg1-2ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-gpu2.4", ver:"2.4.8+dfsg1-2ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-highgui2.4", ver:"2.4.8+dfsg1-2ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-imgproc2.4", ver:"2.4.8+dfsg1-2ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-legacy2.4", ver:"2.4.8+dfsg1-2ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-ml2.4", ver:"2.4.8+dfsg1-2ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-objdetect2.4", ver:"2.4.8+dfsg1-2ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-ocl2.4", ver:"2.4.8+dfsg1-2ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-photo2.4", ver:"2.4.8+dfsg1-2ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-stitching2.4", ver:"2.4.8+dfsg1-2ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-superres2.4", ver:"2.4.8+dfsg1-2ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-ts2.4", ver:"2.4.8+dfsg1-2ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-video2.4", ver:"2.4.8+dfsg1-2ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-videostab2.4", ver:"2.4.8+dfsg1-2ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv2.4-jni", ver:"2.4.8+dfsg1-2ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-calib3d2.4v5", ver:"2.4.9.1+dfsg-1.5ubuntu1.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-contrib2.4v5", ver:"2.4.9.1+dfsg-1.5ubuntu1.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-core2.4v5", ver:"2.4.9.1+dfsg-1.5ubuntu1.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-features2d2.4v5", ver:"2.4.9.1+dfsg-1.5ubuntu1.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-flann2.4v5", ver:"2.4.9.1+dfsg-1.5ubuntu1.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-gpu2.4v5", ver:"2.4.9.1+dfsg-1.5ubuntu1.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-highgui2.4v5", ver:"2.4.9.1+dfsg-1.5ubuntu1.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-imgproc2.4v5", ver:"2.4.9.1+dfsg-1.5ubuntu1.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-legacy2.4v5", ver:"2.4.9.1+dfsg-1.5ubuntu1.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-ml2.4v5", ver:"2.4.9.1+dfsg-1.5ubuntu1.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-objdetect2.4v5", ver:"2.4.9.1+dfsg-1.5ubuntu1.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-ocl2.4v5", ver:"2.4.9.1+dfsg-1.5ubuntu1.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-photo2.4v5", ver:"2.4.9.1+dfsg-1.5ubuntu1.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-stitching2.4v5", ver:"2.4.9.1+dfsg-1.5ubuntu1.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-superres2.4v5", ver:"2.4.9.1+dfsg-1.5ubuntu1.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-ts2.4v5", ver:"2.4.9.1+dfsg-1.5ubuntu1.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-video2.4v5", ver:"2.4.9.1+dfsg-1.5ubuntu1.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-videostab2.4v5", ver:"2.4.9.1+dfsg-1.5ubuntu1.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv2.4-jni", ver:"2.4.9.1+dfsg-1.5ubuntu1.1+esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-calib3d3.2", ver:"3.2.0+dfsg-4ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-contrib3.2", ver:"3.2.0+dfsg-4ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-core3.2", ver:"3.2.0+dfsg-4ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-dev", ver:"3.2.0+dfsg-4ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-features2d3.2", ver:"3.2.0+dfsg-4ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-flann3.2", ver:"3.2.0+dfsg-4ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-highgui3.2", ver:"3.2.0+dfsg-4ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-imgcodecs3.2", ver:"3.2.0+dfsg-4ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-imgproc3.2", ver:"3.2.0+dfsg-4ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-ml3.2", ver:"3.2.0+dfsg-4ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-objdetect3.2", ver:"3.2.0+dfsg-4ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-photo3.2", ver:"3.2.0+dfsg-4ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-shape3.2", ver:"3.2.0+dfsg-4ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-stitching3.2", ver:"3.2.0+dfsg-4ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-superres3.2", ver:"3.2.0+dfsg-4ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-video3.2", ver:"3.2.0+dfsg-4ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-videoio3.2", ver:"3.2.0+dfsg-4ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-videostab3.2", ver:"3.2.0+dfsg-4ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv-viz3.2", ver:"3.2.0+dfsg-4ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopencv3.2-jni", ver:"3.2.0+dfsg-4ubuntu0.1+esm3", rls:"UBUNTU18.04 LTS"))) {
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
