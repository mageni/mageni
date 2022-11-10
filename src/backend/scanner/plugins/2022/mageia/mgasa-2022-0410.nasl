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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0410");
  script_cve_id("CVE-2022-2519", "CVE-2022-2520", "CVE-2022-2521", "CVE-2022-3570", "CVE-2022-3598");
  script_tag(name:"creation_date", value:"2022-11-09 04:29:05 +0000 (Wed, 09 Nov 2022)");
  script_version("2022-11-09T04:29:05+0000");
  script_tag(name:"last_modification", value:"2022-11-09 04:29:05 +0000 (Wed, 09 Nov 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-21 20:57:00 +0000 (Fri, 21 Oct 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0410)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0410");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0410.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30999");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/J7SXFRT2D5U4KU46YFMYHBVPQ56UKZ3V/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5705-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtiff' package(s) announced via the MGASA-2022-0410 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"There is a double free or corruption in rotateImage() at tiffcrop.c:8839
found in libtiff 4.4.0rc1. (CVE-2022-2519)

A flaw was found in libtiff 4.4.0rc1. There is a sysmalloc assertion fail
in rotateImage() at tiffcrop.c:8621 that can cause program crash when
reading a crafted input. (CVE-2022-2520)

It was found in libtiff 4.4.0rc1 that there is an invalid pointer free
operation in TIFFClose() at tif_close.c:131 called by tiffcrop.c:2522 that
can cause a program crash and denial of service while processing crafted
input. (CVE-2022-2521)

Multiple heap buffer overflows in tiffcrop.c utility in libtiff library
Version 4.4.0 allows attacker to trigger unsafe or out of bounds memory
access via crafted TIFF image file which could result into application
crash, potential information disclosure or any other context-dependent
impact. (CVE-2022-3570)

LibTIFF 4.4.0 has an out-of-bounds write in
extractContigSamplesShifted24bits in tools/tiffcrop.c:3604, allowing
attackers to cause a denial-of-service via a crafted tiff file.
(CVE-2022-3598)");

  script_tag(name:"affected", value:"'libtiff' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff-devel", rpm:"lib64tiff-devel~4.2.0~1.9.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff-static-devel", rpm:"lib64tiff-static-devel~4.2.0~1.9.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff5", rpm:"lib64tiff5~4.2.0~1.9.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~4.2.0~1.9.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.2.0~1.9.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-progs", rpm:"libtiff-progs~4.2.0~1.9.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-static-devel", rpm:"libtiff-static-devel~4.2.0~1.9.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5", rpm:"libtiff5~4.2.0~1.9.mga8", rls:"MAGEIA8"))) {
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
