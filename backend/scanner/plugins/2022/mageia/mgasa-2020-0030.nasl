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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0030");
  script_cve_id("CVE-2019-14491", "CVE-2019-14492", "CVE-2019-15939");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-02 03:15:00 +0000 (Mon, 02 Dec 2019)");

  script_name("Mageia: Security Advisory (MGASA-2020-0030)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0030");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0030.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25855");
  script_xref(name:"URL", value:"http://lists.suse.com/pipermail/sle-security-updates/2019-December/006214.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2019-12/msg00073.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opencv' package(s) announced via the MGASA-2020-0030 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:

An issue was discovered in OpenCV before 3.4.7 and 4.x before 4.1.1.
There is an out of bounds read in the function cv::predictOrdered
<cv::HaarEvaluator> in modules/objdetect/src/cascadedetect.hpp, which
leads to denial of service. (CVE-2019-14491)

An issue was discovered in OpenCV before 3.4.7 and 4.x before 4.1.1.
There is an out of bounds read/write in the function HaarEvaluator::
OptFeature::calc in modules/objdetect/src/cascadedetect.hpp, which
leads to denial of service. (CVE-2019-14492)

An issue was discovered in OpenCV 4.1.0. There is a divide-by-zero error
in cv::HOGDescriptor::getDescriptorSize in modules/objdetect/src/hog.cpp.
(CVE-2019-15939)");

  script_tag(name:"affected", value:"'opencv' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_aruco3.4", rpm:"lib64opencv_aruco3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_bgsegm3.4", rpm:"lib64opencv_bgsegm3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_bioinspired3.4", rpm:"lib64opencv_bioinspired3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_calib3d3.4", rpm:"lib64opencv_calib3d3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_ccalib3.4", rpm:"lib64opencv_ccalib3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_core3.4", rpm:"lib64opencv_core3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_datasets3.4", rpm:"lib64opencv_datasets3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_dnn3.4", rpm:"lib64opencv_dnn3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_dnn_objdetect3.4", rpm:"lib64opencv_dnn_objdetect3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_dpm3.4", rpm:"lib64opencv_dpm3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_features2d3.4", rpm:"lib64opencv_features2d3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_flann3.4", rpm:"lib64opencv_flann3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_freetype3.4", rpm:"lib64opencv_freetype3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_fuzzy3.4", rpm:"lib64opencv_fuzzy3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_hfs3.4", rpm:"lib64opencv_hfs3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_highgui3.4", rpm:"lib64opencv_highgui3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_img_hash3.4", rpm:"lib64opencv_img_hash3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_imgcodecs3.4", rpm:"lib64opencv_imgcodecs3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_imgproc3.4", rpm:"lib64opencv_imgproc3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_line_descriptor3.4", rpm:"lib64opencv_line_descriptor3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_ml3.4", rpm:"lib64opencv_ml3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_objdetect3.4", rpm:"lib64opencv_objdetect3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_optflow3.4", rpm:"lib64opencv_optflow3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_phase_unwrapping3.4", rpm:"lib64opencv_phase_unwrapping3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_photo3.4", rpm:"lib64opencv_photo3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_plot3.4", rpm:"lib64opencv_plot3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_reg3.4", rpm:"lib64opencv_reg3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_rgbd3.4", rpm:"lib64opencv_rgbd3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_saliency3.4", rpm:"lib64opencv_saliency3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_shape3.4", rpm:"lib64opencv_shape3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_stereo3.4", rpm:"lib64opencv_stereo3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_stitching3.4", rpm:"lib64opencv_stitching3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_structured_light3.4", rpm:"lib64opencv_structured_light3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_superres3.4", rpm:"lib64opencv_superres3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_surface_matching3.4", rpm:"lib64opencv_surface_matching3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_text3.4", rpm:"lib64opencv_text3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_tracking3.4", rpm:"lib64opencv_tracking3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_video3.4", rpm:"lib64opencv_video3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_videoio3.4", rpm:"lib64opencv_videoio3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_videostab3.4", rpm:"lib64opencv_videostab3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_ximgproc3.4", rpm:"lib64opencv_ximgproc3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_xobjdetect3.4", rpm:"lib64opencv_xobjdetect3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opencv_xphoto3.4", rpm:"lib64opencv_xphoto3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_aruco3.4", rpm:"libopencv_aruco3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_bgsegm3.4", rpm:"libopencv_bgsegm3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_bioinspired3.4", rpm:"libopencv_bioinspired3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_calib3d3.4", rpm:"libopencv_calib3d3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_ccalib3.4", rpm:"libopencv_ccalib3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_core3.4", rpm:"libopencv_core3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_datasets3.4", rpm:"libopencv_datasets3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_dnn3.4", rpm:"libopencv_dnn3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_dnn_objdetect3.4", rpm:"libopencv_dnn_objdetect3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_dpm3.4", rpm:"libopencv_dpm3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_features2d3.4", rpm:"libopencv_features2d3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_flann3.4", rpm:"libopencv_flann3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_freetype3.4", rpm:"libopencv_freetype3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_fuzzy3.4", rpm:"libopencv_fuzzy3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_hfs3.4", rpm:"libopencv_hfs3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_highgui3.4", rpm:"libopencv_highgui3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_img_hash3.4", rpm:"libopencv_img_hash3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_imgcodecs3.4", rpm:"libopencv_imgcodecs3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_imgproc3.4", rpm:"libopencv_imgproc3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_line_descriptor3.4", rpm:"libopencv_line_descriptor3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_ml3.4", rpm:"libopencv_ml3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_objdetect3.4", rpm:"libopencv_objdetect3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_optflow3.4", rpm:"libopencv_optflow3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_phase_unwrapping3.4", rpm:"libopencv_phase_unwrapping3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_photo3.4", rpm:"libopencv_photo3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_plot3.4", rpm:"libopencv_plot3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_reg3.4", rpm:"libopencv_reg3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_rgbd3.4", rpm:"libopencv_rgbd3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_saliency3.4", rpm:"libopencv_saliency3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_shape3.4", rpm:"libopencv_shape3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_stereo3.4", rpm:"libopencv_stereo3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_stitching3.4", rpm:"libopencv_stitching3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_structured_light3.4", rpm:"libopencv_structured_light3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_superres3.4", rpm:"libopencv_superres3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_surface_matching3.4", rpm:"libopencv_surface_matching3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_text3.4", rpm:"libopencv_text3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_tracking3.4", rpm:"libopencv_tracking3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_video3.4", rpm:"libopencv_video3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_videoio3.4", rpm:"libopencv_videoio3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_videostab3.4", rpm:"libopencv_videostab3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_ximgproc3.4", rpm:"libopencv_ximgproc3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_xobjdetect3.4", rpm:"libopencv_xobjdetect3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopencv_xphoto3.4", rpm:"libopencv_xphoto3.4~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opencv", rpm:"opencv~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opencv-devel", rpm:"opencv-devel~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opencv-samples", rpm:"opencv-samples~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-opencv", rpm:"python2-opencv~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-opencv", rpm:"python3-opencv~3.4.5~2.1.mga7", rls:"MAGEIA7"))) {
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
