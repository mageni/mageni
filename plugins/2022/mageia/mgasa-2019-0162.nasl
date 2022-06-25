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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0162");
  script_cve_id("CVE-2019-1787", "CVE-2019-1788", "CVE-2019-1789");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-07 15:55:00 +0000 (Thu, 07 Nov 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0162)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0162");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0162.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24704");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/3940-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the MGASA-2019-0162 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:

A vulnerability in the Portable Document Format (PDF) scanning functionality
of Clam AntiVirus (ClamAV) Software versions 0.101.1 and prior could allow
an unauthenticated, remote attacker to cause a denial of service (DoS)
condition on an affected device. The vulnerability is due to a lack of
proper data handling mechanisms within the device buffer while indexing
remaining file data on an affected device. An attacker could exploit this
vulnerability by sending crafted PDF files to an affected device. A
successful exploit could allow the attacker to cause a heap buffer
out-of-bounds read condition, resulting in a crash that could result in a
denial of service condition on an affected device. (CVE-2019-1787)

A vulnerability in the Object Linking & Embedding (OLE2) file scanning
functionality of Clam AntiVirus (ClamAV) Software versions 0.101.1 and prior
could allow an unauthenticated, remote attacker to cause a denial of service
condition on an affected device. The vulnerability is due to a lack of
proper input and validation checking mechanisms for OLE2 files sent an
affected device. An attacker could exploit this vulnerability by sending
malformed OLE2 files to the device running an affected version ClamAV
Software. An exploit could allow the attacker to cause an out-of-bounds
write condition, resulting in a crash that could result in a denial of
service condition on an affected device. (CVE-2019-1788)

An out-of-bounds heap read condition when scanning PE files. (CVE-2019-1789)");

  script_tag(name:"affected", value:"'clamav' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.100.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-db", rpm:"clamav-db~0.100.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-milter", rpm:"clamav-milter~0.100.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamd", rpm:"clamd~0.100.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64clamav-devel", rpm:"lib64clamav-devel~0.100.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64clamav7", rpm:"lib64clamav7~0.100.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav-devel", rpm:"libclamav-devel~0.100.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav7", rpm:"libclamav7~0.100.3~1.mga6", rls:"MAGEIA6"))) {
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
