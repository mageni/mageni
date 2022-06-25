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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0211");
  script_cve_id("CVE-2017-11332", "CVE-2017-11358", "CVE-2017-11359", "CVE-2017-15372", "CVE-2017-15642", "CVE-2017-18189");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-31T07:41:30+0000");
  script_tag(name:"last_modification", value:"2022-01-31 07:41:30 +0000 (Mon, 31 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-24 15:16:00 +0000 (Thu, 24 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2018-0211)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0211");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0211.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22615");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sox, sox' package(s) announced via the MGASA-2018-0211 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for sox fixes the following security issues:

* CVE-2017-11332: Fixed the startread function in wav.c, which allowed
remote attackers to cause a DoS (divide-by-zero) via crafted wav file.
* CVE-2017-11358: Fixed the read_samples function in hcom.c, which
allowed remote attackers to cause a DoS (invalid memory read) via
crafted hcom file.
* CVE-2017-11359: Fixed the wavwritehdr function in wav.c, which allowed
remote attackers to cause a DoS (divide-by-zero) when converting a
crafted snd file to a wav file.
* CVE-2017-15372: Fixed a stack-based buffer overflow in the
lsx_ms_adpcm_block_expand_i function of adpcm.c, which allowed remote
attackers to cause a DoS during conversion of a crafted audio file.
* CVE-2017-15642: Fixed an Use-After-Free vulnerability in
lsx_aiffstartread in aiff.c, which could be triggered by an attacker by
providing a malformed AIFF file.
* CVE-2017-18189: In the startread function in xa.c in Sound eXchange
(SoX) through 14.4.2, a corrupt header specifying zero channels triggers
an infinite loop with a resultant NULL pointer dereference, which may
allow a remote attacker to cause a denial-of-service.");

  script_tag(name:"affected", value:"'sox, sox' package(s) on Mageia 5, Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64sox-devel", rpm:"lib64sox-devel~14.4.1~6.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sox2", rpm:"lib64sox2~14.4.1~6.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsox-devel", rpm:"libsox-devel~14.4.1~6.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsox2", rpm:"libsox2~14.4.1~6.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sox", rpm:"sox~14.4.1~6.3.mga5", rls:"MAGEIA5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"lib64sox-devel", rpm:"lib64sox-devel~14.4.2~7.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sox3", rpm:"lib64sox3~14.4.2~7.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsox-devel", rpm:"libsox-devel~14.4.2~7.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsox3", rpm:"libsox3~14.4.2~7.3.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sox", rpm:"sox~14.4.2~7.3.mga6", rls:"MAGEIA6"))) {
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
