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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2269");
  script_cve_id("CVE-2022-1920", "CVE-2022-1921", "CVE-2022-1922", "CVE-2022-1923", "CVE-2022-1924", "CVE-2022-1925", "CVE-2022-2122");
  script_tag(name:"creation_date", value:"2022-08-18 04:37:33 +0000 (Thu, 18 Aug 2022)");
  script_version("2022-08-18T04:37:33+0000");
  script_tag(name:"last_modification", value:"2022-08-18 04:37:33 +0000 (Thu, 18 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-26 22:30:00 +0000 (Tue, 26 Jul 2022)");

  script_name("Huawei EulerOS: Security Advisory for gstreamer1-plugins-good (EulerOS-SA-2022-2269)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2269");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2269");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'gstreamer1-plugins-good' package(s) announced via the EulerOS-SA-2022-2269 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Integer overflow in avidemux element in gst_avi_demux_invert function which allows a heap overwrite while parsing avi files. Potential for arbitrary code execution through heap overwrite.(CVE-2022-1921)

DOS / potential heap overwrite in qtdemux using zlib decompression. Integer overflow in qtdemux element in qtdemux_inflate function which causes a segfault, or could cause a heap overwrite, depending on libc and OS. Depending on the libc used, and the underlying OS capabilities, it could be just a segfault or a heap overwrite.(CVE-2022-2122)

DOS / potential heap overwrite in mkv demuxing using HEADERSTRIP decompression. Integer overflow in matroskaparse element in gst_matroska_decompress_data function which causes a heap overflow. Due to restrictions on chunk sizes in the matroskademux element, the overflow can't be triggered, however the matroskaparse element has no size checks.(CVE-2022-1925)

DOS / potential heap overwrite in mkv demuxing using zlib decompression. Integer overflow in matroskademux element in gst_matroska_decompress_data function which causes a segfault, or could cause a heap overwrite, depending on libc and OS. Depending on the libc used, and the underlying OS capabilities, it could be just a segfault or a heap overwrite. If the libc uses mmap for large chunks, and the OS supports mmap, then it is just a segfault (because the realloc before the integer overflow will use mremap to reduce the size of the chunk, and it will start to write to unmapped memory). However, if using a libc implementation that does not use mmap, or if the OS does not support mmap while using libc, then this could result in a heap overwrite.(CVE-2022-1922)

DOS / potential heap overwrite in mkv demuxing using lzo decompression. Integer overflow in matroskademux element in lzo decompression function which causes a segfault, or could cause a heap overwrite, depending on libc and OS. Depending on the libc used, and the underlying OS capabilities, it could be just a segfault or a heap overwrite. If the libc uses mmap for large chunks, and the OS supports mmap, then it is just a segfault (because the realloc before the integer overflow will use mremap to reduce the size of the chunk, and it will start to write to unmapped memory). However, if using a libc implementation that does not use mmap, or if the OS does not support mmap while using libc, then this could result in a heap overwrite.(CVE-2022-1924)

Integer overflow in matroskademux element in gst_matroska_demux_add_wvpk_header function which allows a heap overwrite while parsing matroska files. Potential for arbitrary code execution through heap overwrite.(CVE-2022-1920)

DOS / potential heap overwrite in mkv demuxing using bzip decompression. Integer overflow in matroskademux element in bzip decompression function which causes a segfault, or could cause a heap overwrite, depending on libc and OS. Depending on the libc used, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'gstreamer1-plugins-good' package(s) on Huawei EulerOS V2.0SP5.");

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

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugins-good", rpm:"gstreamer1-plugins-good~1.10.4~2.h3.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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
