###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_1385_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for opencv openSUSE-SU-2018:1385-1 (opencv)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.851755");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-05-24 05:46:28 +0200 (Thu, 24 May 2018)");
  script_cve_id("CVE-2016-1516", "CVE-2017-12597", "CVE-2017-12598", "CVE-2017-12599",
                "CVE-2017-12600", "CVE-2017-12601", "CVE-2017-12602", "CVE-2017-12603",
                "CVE-2017-12604", "CVE-2017-12605", "CVE-2017-12606", "CVE-2017-12862",
                "CVE-2017-12863", "CVE-2017-12864", "CVE-2017-14136");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for opencv openSUSE-SU-2018:1385-1 (opencv)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'opencv'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"This update for opencv fixes the following issues:

  Security issues fixed:

  - CVE-2016-1516: OpenCV had a double free issue that allowed attackers to
  execute arbitrary code. (boo#1033152)

  - CVE-2017-14136: OpenCV had an out-of-bounds write error in the function
  FillColorRow1 in utils.cpp when reading an image file by using
  cv::imread. NOTE: this vulnerability exists because of an incomplete fix
  for CVE-2017-12597. (boo#1057146)

  - CVE-2017-12606: OpenCV had an out-of-bounds write error in the function
  FillColorRow4 in utils.cpp when reading an image file by using
  cv::imread. (boo#1052451)

  - CVE-2017-12604: OpenCV had an out-of-bounds write error in the
  FillUniColor function in utils.cpp when reading an image file by using
  cv::imread. (boo#1052454)

  - CVE-2017-12603: OpenCV had an invalid write in the
  cv::RLByteStream::getBytes function in modules/imgcodecs/src/bitstrm.cpp
  when reading an image file by using cv::imread, as demonstrated by the
  2-opencv-heapoverflow-fseek test case. (boo#1052455)

  - CVE-2017-12602: OpenCV had a denial of service (memory consumption)
  issue, as demonstrated by the 10-opencv-dos-memory-exhaust test case.
  (boo#1052456)

  - CVE-2017-12601: OpenCV had a buffer overflow in the
  cv::BmpDecoder::readData function in modules/imgcodecs/src/grfmt_bmp.cpp
  when reading an image file by using cv::imread, as demonstrated by the
  4-buf-overflow-readData-memcpy test case. (boo#1052457)

  - CVE-2017-12600: OpenCV had a denial of service (CPU consumption) issue,
  as demonstrated by the 11-opencv-dos-cpu-exhaust test case. (boo#1052459)

  - CVE-2017-12599: OpenCV had an out-of-bounds read error in the function
  icvCvt_BGRA2BGR_8u_C4C3R when reading an image file by using cv::imread.
  (boo#1052461)

  - CVE-2017-12598: OpenCV had an out-of-bounds read error in the
  cv::RBaseStream::readBlock function in modules/imgcodecs/src/bitstrm.cpp
  when reading an image file by using cv::imread, as demonstrated by the
  8-opencv-invalid-read-fread test case. (boo#1052462)

  - CVE-2017-12597: OpenCV had an out-of-bounds write error in the function
  FillColorRow1 in utils.cpp when reading an image file by using
  cv::imread. (boo#1052465)

  - CVE-2017-12864: In opencv/modules/imgcodecs/src/grfmt_pxm.cpp, function
  ReadNumber did not checkout the input length, which lead to integer
  overflow. If the image is from remote, may lead to remote code execution
  or denial of service. (boo#1054019)

  - CVE-2017-12863: In opencv/modules/imgcodecs/src/grfmt_pxm.cpp, function
  PxMDecoder::readData has an integer overflow when calculate src_pitch.
  If ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"opencv on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-05/msg00094.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"libopencv-qt56_3", rpm:"libopencv-qt56_3~3.1.0~4.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopencv-qt56_3-debuginfo", rpm:"libopencv-qt56_3-debuginfo~3.1.0~4.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopencv3_1", rpm:"libopencv3_1~3.1.0~4.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopencv3_1-debuginfo", rpm:"libopencv3_1-debuginfo~3.1.0~4.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opencv", rpm:"opencv~3.1.0~4.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opencv-debuginfo", rpm:"opencv-debuginfo~3.1.0~4.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opencv-debugsource", rpm:"opencv-debugsource~3.1.0~4.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opencv-devel", rpm:"opencv-devel~3.1.0~4.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opencv-doc", rpm:"opencv-doc~3.1.0~4.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opencv-qt5", rpm:"opencv-qt5~3.1.0~4.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opencv-qt5-debuginfo", rpm:"opencv-qt5-debuginfo~3.1.0~4.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opencv-qt5-debugsource", rpm:"opencv-qt5-debugsource~3.1.0~4.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opencv-qt5-devel", rpm:"opencv-qt5-devel~3.1.0~4.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opencv-qt5-doc", rpm:"opencv-qt5-doc~3.1.0~4.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-opencv", rpm:"python-opencv~3.1.0~4.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-opencv-debuginfo", rpm:"python-opencv-debuginfo~3.1.0~4.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-opencv-qt5", rpm:"python-opencv-qt5~3.1.0~4.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-opencv-qt5-debuginfo", rpm:"python-opencv-qt5-debuginfo~3.1.0~4.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python3-opencv", rpm:"python3-opencv~3.1.0~4.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python3-opencv-debuginfo", rpm:"python3-opencv-debuginfo~3.1.0~4.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python3-opencv-qt5", rpm:"python3-opencv-qt5~3.1.0~4.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python3-opencv-qt5-debuginfo", rpm:"python3-opencv-qt5-debuginfo~3.1.0~4.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
