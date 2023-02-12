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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5167.1");
  script_cve_id("CVE-2020-20445", "CVE-2020-20446", "CVE-2020-20451", "CVE-2020-20453", "CVE-2020-20892", "CVE-2020-20902", "CVE-2020-21041", "CVE-2020-21688", "CVE-2020-21697", "CVE-2020-22016", "CVE-2020-22020", "CVE-2020-22021", "CVE-2020-22022", "CVE-2020-22025", "CVE-2020-22031", "CVE-2020-22032", "CVE-2020-22037", "CVE-2020-22040", "CVE-2020-22041", "CVE-2020-22042", "CVE-2020-22044", "CVE-2020-22046", "CVE-2020-22049", "CVE-2020-22054", "CVE-2020-35965", "CVE-2021-3566", "CVE-2021-38114", "CVE-2021-38171", "CVE-2021-38291");
  script_tag(name:"creation_date", value:"2023-01-27 04:10:43 +0000 (Fri, 27 Jan 2023)");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-30 15:37:00 +0000 (Mon, 30 Aug 2021)");

  script_name("Ubuntu: Security Advisory (USN-5167-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5167-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5167-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg' package(s) announced via the USN-5167-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that FFmpeg did not properly verify certain input when
processing video and audio files. An attacker could possibly use this to send
specially crafted input to the application, force a division by zero, and
cause a denial of service (application crash). (CVE-2020-20445, CVE-2020-20446,
CVE-2020-20453, CVE-2020-20892)

It was discovered that FFmpeg did not properly perform certain bit shift and
memory operations. An attacker could possibly use this issue to expose
sensitive information. (CVE-2020-20902)

It was discovered that FFmpeg did not properly perform memory management
operations in various of its functions. An attacker could possibly use this
issue to send specially crafted input to the application and cause a denial of
service (application crash) or execute arbitrary code. (CVE-2020-21041,
CVE-2020-20451, CVE-2020-21688, CVE-2020-21697, CVE-2020-22020,
CVE-2020-22021, CVE-2020-22022, CVE-2020-22025, CVE-2020-22031,
CVE-2020-22032, CVE-2020-22037, CVE-2020-22040, CVE-2020-22041,
CVE-2020-22042, CVE-2020-22044)

It was discovered that FFmpeg did not properly perform memory management
operations in various of its functions. An attacker could possibly use this
issue to send specially crafted input to the application and cause a denial of
service (application crash) or execute arbitrary code. (CVE-2020-22016,
CVE-2020-22046, CVE-2020-22049, CVE-2020-22054)

It was discovered that FFmpeg did not properly perform memory management
operations in various of its functions. An attacker could possibly use this
issue to send specially crafted input to the application and cause a denial of
service (application crash) or execute arbitrary code. (CVE-2020-35965)

It was discovered that FFmpeg did not properly handle data assigned to the tty
demuxer. An attacker could possibly use this issue to send specially crafted
input to the application and expose sensitive information. (CVE-2021-3566)

It was discovered that FFmpeg did not perform checks on function return
values when encoding and formatting input video and audio files. An attacker
could possibly use this issue to cause a denial of service (application crash)
or execute arbitrary code. (CVE-2021-38114, CVE-2021-38171)

It was discovered that FFmpeg did not properly sanitize function returned data
when calculating frame duration values. An attacker could possibly use this
issue to cause an assertion failure and then cause a denial of service
(application crash). (CVE-2021-38291)");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ffmpeg", ver:"7:2.8.17-0ubuntu0.1+esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-extra", ver:"7:2.8.17-0ubuntu0.1+esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-ffmpeg-extra56", ver:"7:2.8.17-0ubuntu0.1+esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-ffmpeg56", ver:"7:2.8.17-0ubuntu0.1+esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavdevice-ffmpeg56", ver:"7:2.8.17-0ubuntu0.1+esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter-ffmpeg5", ver:"7:2.8.17-0ubuntu0.1+esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat-ffmpeg56", ver:"7:2.8.17-0ubuntu0.1+esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavresample-ffmpeg2", ver:"7:2.8.17-0ubuntu0.1+esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavutil-ffmpeg54", ver:"7:2.8.17-0ubuntu0.1+esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpostproc-ffmpeg53", ver:"7:2.8.17-0ubuntu0.1+esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswresample-ffmpeg1", ver:"7:2.8.17-0ubuntu0.1+esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswscale-ffmpeg3", ver:"7:2.8.17-0ubuntu0.1+esm4", rls:"UBUNTU16.04 LTS"))) {
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
