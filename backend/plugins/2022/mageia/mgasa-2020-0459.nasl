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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0459");
  script_cve_id("CVE-2017-14628", "CVE-2017-14629", "CVE-2017-14630", "CVE-2017-14631", "CVE-2017-14636", "CVE-2017-14637", "CVE-2017-16663", "CVE-2018-12578", "CVE-2018-12601", "CVE-2018-7487", "CVE-2018-7551", "CVE-2018-7553", "CVE-2018-7554");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-27 16:43:00 +0000 (Wed, 27 Sep 2017)");

  script_name("Mageia: Security Advisory (MGASA-2020-0459)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0459");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0459.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27746");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-1127");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-1185");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1340");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1463");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sam2p' package(s) announced via the MGASA-2020-0459 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In sam2p 0.49.3, a heap-based buffer overflow exists in the pcxLoadImage24
function of the file in_pcx.cpp. (CVE-2017-14628).

In sam2p 0.49.3, the in_xpm_reader function in in_xpm.cpp has an integer
signedness error, leading to a crash when writing to an out-of-bounds array
element. (CVE-2017-14629).

In sam2p 0.49.3, an integer overflow exists in the pcxLoadImage24 function
of the file in_pcx.cpp, leading to an invalid write operation.
(CVE-2017-14630).

In sam2p 0.49.3, the pcxLoadRaster function in in_pcx.cpp has an integer
signedness error leading to a heap-based buffer overflow. (CVE-2017-14631).

Because of an integer overflow in sam2p 0.49.3, a loop executes 0xffffffff
times, ending with an invalid read of size 1 in the Image::Indexed::sortPal
function in image.cpp. However, this also causes memory corruption because
of an attempted write to the invalid d[0xfffffffe] array element.
(CVE-2017-14636).

In sam2p 0.49.3, there is an invalid read of size 2 in the parse_rgb function
in in_xpm.cpp. However, this can also cause a write to an illegal address.
(CVE-2017-14637).

In sam2p 0.49.4, there are integer overflows (with resultant heap-based buffer
overflows) in input-bmp.ci in the function ReadImage, because 'width * height'
multiplications occur unsafely. (CVE-2017-16663).

There is a heap-based buffer overflow in the LoadPCX function of in_pcx.cpp
in sam2p 0.49.4. A Crafted input will lead to a denial of service or possibly
unspecified other impact. (CVE-2018-7487).

There is an invalid free in MiniPS::delete0 in minips.cpp that leads to a
Segmentation fault in sam2p 0.49.4. A crafted input will lead to a denial of
service or possibly unspecified other impact. (CVE-2018-7551).

There is a heap-based buffer overflow in the pcxLoadRaster function of
in_pcx.cpp in sam2p 0.49.4. A crafted input will lead to a denial of service
or possibly unspecified other impact. (CVE-2018-7553).

There is an invalid free in ReadImage in input-bmp.ci that leads to a
Segmentation fault in sam2p 0.49.4. A crafted input will lead to a denial of
service or possibly unspecified other impact. (CVE-2018-7554).

There is a heap-based buffer overflow in bmp_compress1_row in appliers.cpp
in sam2p 0.49.4 that leads to a denial of service or possibly unspecified
other impact. (CVE-2018-12578).

There is a heap-based buffer overflow in ReadImage in input-tga.ci in sam2p
0.49.4 that leads to a denial of service or possibly unspecified other impact.
(CVE-2018-12601).");

  script_tag(name:"affected", value:"'sam2p' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"sam2p", rpm:"sam2p~0.49.3~2.1.mga7", rls:"MAGEIA7"))) {
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
