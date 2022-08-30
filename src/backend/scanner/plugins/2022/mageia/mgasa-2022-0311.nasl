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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0311");
  script_cve_id("CVE-2022-24805", "CVE-2022-24806", "CVE-2022-24807", "CVE-2022-24808", "CVE-2022-24809", "CVE-2022-24810");
  script_tag(name:"creation_date", value:"2022-08-29 12:18:03 +0000 (Mon, 29 Aug 2022)");
  script_version("2022-08-29T12:18:03+0000");
  script_tag(name:"last_modification", value:"2022-08-29 12:18:03 +0000 (Mon, 29 Aug 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2022-0311)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0311");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0311.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30697");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5543-1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/FX75KKGMO5XMV6JMQZF6KOG3JPFNQBY7/");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5209");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-snmp' package(s) announced via the MGASA-2022-0311 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow in the handling of the INDEX of NET-SNMP-VACM-MIB can
cause an out-of-bounds memory access. (CVE-2022-24805)
Buffer overflow and out of bounds memory access. (CVE-2022-24806)
A malformed OID in a SET request to
SNMP-VIEW-BASED-ACM-MIB::vacmAccessTable can cause an out-of-bounds memory
access. (CVE-2022-24807)
A malformed OID in a SET request to NET-SNMP-AGENT-MIB::nsLogTable can
cause a NULL pointer dereference. (CVE-2022-24808)
A malformed OID in a GET-NEXT to the nsVacmAccessTable can cause a NULL
pointer dereference. (CVE-2022-24809)
A malformed OID in a SET to the nsVacmAccessTable can cause a NULL pointer
dereference. (CVE-2022-24810)");

  script_tag(name:"affected", value:"'net-snmp' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64net-snmp-devel", rpm:"lib64net-snmp-devel~5.9~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64net-snmp40", rpm:"lib64net-snmp40~5.9~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnet-snmp-devel", rpm:"libnet-snmp-devel~5.9~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnet-snmp40", rpm:"libnet-snmp40~5.9~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.9~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-mibs", rpm:"net-snmp-mibs~5.9~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-tkmib", rpm:"net-snmp-tkmib~5.9~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-trapd", rpm:"net-snmp-trapd~5.9~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-utils", rpm:"net-snmp-utils~5.9~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-NetSNMP", rpm:"perl-NetSNMP~5.9~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-netsnmp", rpm:"python3-netsnmp~5.9~1.1.mga8", rls:"MAGEIA8"))) {
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
