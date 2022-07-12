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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0346");
  script_cve_id("CVE-2019-15142", "CVE-2019-15143", "CVE-2019-15144", "CVE-2019-15145", "CVE-2019-18804");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-27 16:14:00 +0000 (Thu, 27 May 2021)");

  script_name("Mageia: Security Advisory (MGASA-2019-0346)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0346");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0346.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25730");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/4198-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'djvulibre' package(s) announced via the MGASA-2019-0346 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:

In DjVuLibre 3.5.27, DjVmDir.cpp in the DJVU reader component allows
attackers to cause a denial-of-service (application crash in
GStringRep::strdup in libdjvu/GString.cpp caused by a heap-based buffer
over-read) by crafting a DJVU file. (CVE-2019-15142)

In DjVuLibre 3.5.27, the bitmap reader component allows attackers to
cause a denial-of-service error (resource exhaustion caused by a
GBitmap::read_rle_raw infinite loop) by crafting a corrupted image file,
related to libdjvu/DjVmDir.cpp and libdjvu/GBitmap.cpp. (CVE-2019-15143)

In DjVuLibre 3.5.27, the sorting functionality (aka
GArrayTemplate<TYPE>::sort) allows attackers to cause a denial-of-service
(application crash due to an Uncontrolled Recursion) by crafting a PBM
image file that is mishandled in libdjvu/GContainer.h. (CVE-2019-15144)

DjVuLibre 3.5.27 allows attackers to cause a denial-of-service attack
(application crash via an out-of-bounds read) by crafting a corrupted JB2
image file that is mishandled in JB2Dict::JB2Codec::get_direct_context in
libdjvu/JB2Image.h because of a missing zero-bytes check in
libdjvu/GBitmap.h. (CVE-2019-15145)

DjVuLibre 3.5.27 has a NULL pointer dereference in the function
DJVU::filter_fv at IW44EncodeCodec.cpp. (CVE-2019-18804)");

  script_tag(name:"affected", value:"'djvulibre' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"djvulibre", rpm:"djvulibre~3.5.27~5.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64djvulibre-devel", rpm:"lib64djvulibre-devel~3.5.27~5.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64djvulibre21", rpm:"lib64djvulibre21~3.5.27~5.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdjvulibre-devel", rpm:"libdjvulibre-devel~3.5.27~5.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdjvulibre21", rpm:"libdjvulibre21~3.5.27~5.1.mga7", rls:"MAGEIA7"))) {
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
