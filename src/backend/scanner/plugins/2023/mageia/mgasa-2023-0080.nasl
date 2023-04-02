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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0080");
  script_cve_id("CVE-2023-0795", "CVE-2023-0796", "CVE-2023-0797", "CVE-2023-0798", "CVE-2023-0799", "CVE-2023-0800", "CVE-2023-0801", "CVE-2023-0802", "CVE-2023-0803", "CVE-2023-0804");
  script_tag(name:"creation_date", value:"2023-03-28 00:26:44 +0000 (Tue, 28 Mar 2023)");
  script_version("2023-03-28T10:09:39+0000");
  script_tag(name:"last_modification", value:"2023-03-28 10:09:39 +0000 (Tue, 28 Mar 2023)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-15 16:07:00 +0000 (Wed, 15 Feb 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0080)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0080");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0080.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31585");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3333");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtiff' package(s) announced via the MGASA-2023-0080 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Out-of-bounds read in tiffcrop in tools/tiffcrop.c:3488, allowing
attackers to cause a denial-of-service via a crafted tiff file.
(CVE-2023-0795)

Out-of-bounds read in tiffcrop in tools/tiffcrop.c:3592, allowing
attackers to cause a denial-of-service via a crafted tiff file.
(CVE-2023-0796)

Out-of-bounds read in tiffcrop in libtiff/tif_unix.c:368, invoked by
tools/tiffcrop.c:2903 and tools/tiffcrop.c:6921, allowing attackers to
cause a denial-of-service via a crafted tiff file. (CVE-2023-0797)

Out-of-bounds read in tiffcrop in tools/tiffcrop.c:3400, allowing
attackers to cause a denial-of-service via a crafted tiff file.
(CVE-2023-0798)

Out-of-bounds read in tiffcrop in tools/tiffcrop.c:3701, allowing
attackers to cause a denial-of-service via a crafted tiff file
(CVE-2023-0799)

Out-of-bounds write in tiffcrop in tools/tiffcrop.c:3502, allowing
attackers to cause a denial-of-service via a crafted tiff file.
(CVE-2023-0800)

Out-of-bounds write in tiffcrop in libtiff/tif_unix.c:368, invoked by
tools/tiffcrop.c:2903 and tools/tiffcrop.c:6778, allowing attackers to
cause a denial-of-service via a crafted tiff file. (CVE-2023-0801)

Out-of-bounds write in tiffcrop in tools/tiffcrop.c:3724, allowing
attackers to cause a denial-of-service via a crafted tiff file.
(CVE-2023-0802)

Out-of-bounds write in tiffcrop in tools/tiffcrop.c:3516, allowing
attackers to cause a denial-of-service via a crafted tiff file.
(CVE-2023-0803)

Out-of-bounds write in tiffcrop in tools/tiffcrop.c:3609, allowing
attackers to cause a denial-of-service via a crafted tiff file.
(CVE-2023-0804)");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff-devel", rpm:"lib64tiff-devel~4.2.0~1.14.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff-static-devel", rpm:"lib64tiff-static-devel~4.2.0~1.14.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff5", rpm:"lib64tiff5~4.2.0~1.14.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~4.2.0~1.14.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.2.0~1.14.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-progs", rpm:"libtiff-progs~4.2.0~1.14.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-static-devel", rpm:"libtiff-static-devel~4.2.0~1.14.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5", rpm:"libtiff5~4.2.0~1.14.mga8", rls:"MAGEIA8"))) {
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
