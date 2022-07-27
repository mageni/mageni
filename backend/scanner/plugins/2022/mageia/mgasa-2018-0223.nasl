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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0223");
  script_cve_id("CVE-2004-2779", "CVE-2008-2109", "CVE-2017-11550", "CVE-2017-11551");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-19 16:15:00 +0000 (Mon, 19 Mar 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0223)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0223");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0223.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22802");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libid3tag, libid3tag' package(s) announced via the MGASA-2018-0223 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"id3_utf16_deserialize() in utf16.c in libid3tag through 0.15.1b
misparses ID3v2 tags encoded in UTF-16 with an odd number of bytes,
triggering an endless loop allocating memory until an OOM condition is
reached, leading to denial-of-service (DoS). (CVE-2004-2779)

field.c in the libid3tag 0.15.0b library allows context-dependent
attackers to cause a denial of service (CPU consumption) via an
ID3_FIELD_TYPE_STRINGLIST field that ends in '\0', which triggers an
infinite loop. (CVE-2008-2109)

The id3_ucs4_length function in ucs4.c in libid3tag 0.15.1b allows
remote attackers to cause a denial of service (NULL Pointer Dereference
and application crash) via a crafted mp3 file. (CVE-2017-11550)

The id3_field_parse function in field.c in libid3tag 0.15.1b allows
remote attackers to cause a denial of service (OOM) via a crafted MP3
file. (CVE-2017-11551)");

  script_tag(name:"affected", value:"'libid3tag, libid3tag' package(s) on Mageia 5, Mageia 6.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64id3tag-devel", rpm:"lib64id3tag-devel~0.15.1b~16.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64id3tag0", rpm:"lib64id3tag0~0.15.1b~16.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libid3tag", rpm:"libid3tag~0.15.1b~16.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libid3tag-devel", rpm:"libid3tag-devel~0.15.1b~16.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libid3tag0", rpm:"libid3tag0~0.15.1b~16.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"lib64id3tag-devel", rpm:"lib64id3tag-devel~0.15.1b~17.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64id3tag0", rpm:"lib64id3tag0~0.15.1b~17.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libid3tag", rpm:"libid3tag~0.15.1b~17.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libid3tag-devel", rpm:"libid3tag-devel~0.15.1b~17.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libid3tag0", rpm:"libid3tag0~0.15.1b~17.2.mga6", rls:"MAGEIA6"))) {
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
