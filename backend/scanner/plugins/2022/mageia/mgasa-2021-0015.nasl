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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0015");
  script_cve_id("CVE-2020-15304", "CVE-2020-15305", "CVE-2020-15306", "CVE-2020-16587", "CVE-2020-16588", "CVE-2020-16589");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-11 04:15:00 +0000 (Sun, 11 Jul 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0015)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0015");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0015.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26914");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/LKDRVXORM2VLNHRLFKS3JHRABSHZ5W5M/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4418-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4676-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openexr' package(s) announced via the MGASA-2021-0015 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in OpenEXR before 2.5.2. An invalid tiled input file
could cause invalid memory access in TiledInputFile::TiledInputFile() in
IlmImf/ImfTiledInputFile.cpp, as demonstrated by a NULL pointer dereference
(CVE-2020-15304).

An issue was discovered in OpenEXR before 2.5.2. Invalid input could cause a
use-after-free in DeepScanLineInputFile::DeepScanLineInputFile() in
IlmImf/ImfDeepScanLineInputFile.cpp (CVE-2020-15305).

An issue was discovered in OpenEXR before v2.5.2. Invalid chunkCount attributes
could cause a heap buffer overflow in getChunkOffsetTableSize() in
IlmImf/ImfMisc.cpp (CVE-2020-15306).

A heap-based buffer overflow vulnerability exists in Academy Software
Foundation OpenEXR 2.3.0 in chunkOffsetReconstruction in
ImfMultiPartInputFile.cpp that can cause a denial of service via a crafted EXR
file (CVE-2020-16587).

A Null Pointer Deference issue exists in Academy Software Foundation OpenEXR
2.3.0 in generatePreview in makePreview.cpp that can cause a denial of
service via a crafted EXR file (CVE-2020-16588).

A head-based buffer overflow exists in Academy Software Foundation OpenEXR
2.3.0 in writeTileData in ImfTiledOutputFile.cpp that can cause a denial of
service via a crafted EXR file (CVE-2020-16589).");

  script_tag(name:"affected", value:"'openexr' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64ilmimf2_3_24", rpm:"lib64ilmimf2_3_24~2.3.0~2.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openexr-devel", rpm:"lib64openexr-devel~2.3.0~2.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libilmimf2_3_24", rpm:"libilmimf2_3_24~2.3.0~2.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenexr-devel", rpm:"libopenexr-devel~2.3.0~2.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr", rpm:"openexr~2.3.0~2.3.mga7", rls:"MAGEIA7"))) {
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
