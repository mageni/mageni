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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0415");
  script_cve_id("CVE-2019-13108", "CVE-2019-13109", "CVE-2019-13110", "CVE-2019-13112", "CVE-2019-13113", "CVE-2019-13114", "CVE-2019-17402");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-09 03:15:00 +0000 (Fri, 09 Aug 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0415)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0415");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0415.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25280");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/4056-1/");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/4159-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exiv2' package(s) announced via the MGASA-2019-0415 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:

An integer overflow in Exiv2 through 0.27.1 allows an attacker to cause
a denial of service (SIGSEGV) via a crafted PNG image file, because
PngImage::readMetadata mishandles a zero value for iccOffset.
(CVE-2019-13108)

An integer overflow in Exiv2 through 0.27.1 allows an attacker to cause
a denial of service (SIGSEGV) via a crafted PNG image file, because
PngImage::readMetadata mishandles a chunkLength - iccOffset subtraction.
(CVE-2019-13109)

A CiffDirectory::readDirectory integer overflow and out-of-bounds read
in Exiv2 through 0.27.1 allows an attacker to cause a denial of service
(SIGSEGV) via a crafted CRW image file. (CVE-2019-13110)

A PngChunk::parseChunkContent uncontrolled memory allocation in Exiv2
through 0.27.1 allows an attacker to cause a denial of service (crash
due to an std::bad_alloc exception) via a crafted PNG image file.
(CVE-2019-13112)

Exiv2 through 0.27.1 allows an attacker to cause a denial of service
(crash due to assertion failure) via an invalid data location in a
CRW image file. (CVE-2019-13113)

http.c in Exiv2 through 0.27.1 allows a malicious http server to cause a
denial of service (crash due to a NULL pointer dereference) by returning
a crafted response that lacks a space character. (CVE-2019-13114)

Exiv2 0.27.2 allows attackers to trigger a crash in Exiv2::getULong in
types.cpp when called from Exiv2::Internal::CiffDirectory::readDirectory
in crwimage_int.cpp, because there is no validation of the relationship
of the total size to the offset and size. (CVE-2019-17402)");

  script_tag(name:"affected", value:"'exiv2' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"exiv2", rpm:"exiv2~0.27.1~3.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"exiv2-doc", rpm:"exiv2-doc~0.27.1~3.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64exiv2-devel", rpm:"lib64exiv2-devel~0.27.1~3.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64exiv2_27", rpm:"lib64exiv2_27~0.27.1~3.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2-devel", rpm:"libexiv2-devel~0.27.1~3.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexiv2_27", rpm:"libexiv2_27~0.27.1~3.2.mga7", rls:"MAGEIA7"))) {
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
