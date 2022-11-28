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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4205.1");
  script_cve_id("CVE-2022-24805", "CVE-2022-24806", "CVE-2022-24807", "CVE-2022-24808", "CVE-2022-24809", "CVE-2022-24810");
  script_tag(name:"creation_date", value:"2022-11-24 04:19:01 +0000 (Thu, 24 Nov 2022)");
  script_version("2022-11-24T10:18:54+0000");
  script_tag(name:"last_modification", value:"2022-11-24 10:18:54 +0000 (Thu, 24 Nov 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4205-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4205-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224205-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-snmp' package(s) announced via the SUSE-SU-2022:4205-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for net-snmp fixes the following issues:

 Updated to version 5.9.3 (bsc#1201103, jsc#SLE-11203):

 - CVE-2022-24805: Fixed a buffer overflow in the handling of the INDEX
 of NET-SNMP-VACM-MIB that can cause an out-of-bounds memory access.
 - CVE-2022-24809: Fixed a malformed OID in a GET-NEXT to the
 nsVacmAccessTable that can cause a NULL pointer dereference.
 - CVE-2022-24806: Fixed an improper Input Validation when SETing
 malformed OIDs in master agent and subagent simultaneously.
 - CVE-2022-24807: Fixed a malformed OID in a SET request to
 SNMP-VIEW-BASED-ACM-MIB::vacmAccessTable can cause an out-of-bounds
 memory access.
 - CVE-2022-24808: Fixed a malformed OID in a SET request to
 NET-SNMP-AGENT-MIB::nsLogTable can cause a NULL pointer dereference.
 - CVE-2022-24810: Fixed a malformed OID in a SET to the
 nsVacmAccessTable can cause a NULL pointer dereference.");

  script_tag(name:"affected", value:"'net-snmp' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Basesystem 15-SP4, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP3, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP4.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libsnmp40", rpm:"libsnmp40~5.9.3~150300.15.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsnmp40-debuginfo", rpm:"libsnmp40-debuginfo~5.9.3~150300.15.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.9.3~150300.15.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-debuginfo", rpm:"net-snmp-debuginfo~5.9.3~150300.15.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-debugsource", rpm:"net-snmp-debugsource~5.9.3~150300.15.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.9.3~150300.15.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.9.3~150300.15.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-SNMP-debuginfo", rpm:"perl-SNMP-debuginfo~5.9.3~150300.15.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snmp-mibs", rpm:"snmp-mibs~5.9.3~150300.15.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsnmp40-32bit", rpm:"libsnmp40-32bit~5.9.3~150300.15.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsnmp40-32bit-debuginfo", rpm:"libsnmp40-32bit-debuginfo~5.9.3~150300.15.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libsnmp40", rpm:"libsnmp40~5.9.3~150300.15.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsnmp40-debuginfo", rpm:"libsnmp40-debuginfo~5.9.3~150300.15.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.9.3~150300.15.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-debuginfo", rpm:"net-snmp-debuginfo~5.9.3~150300.15.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-debugsource", rpm:"net-snmp-debugsource~5.9.3~150300.15.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.9.3~150300.15.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.9.3~150300.15.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-SNMP-debuginfo", rpm:"perl-SNMP-debuginfo~5.9.3~150300.15.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snmp-mibs", rpm:"snmp-mibs~5.9.3~150300.15.3.1", rls:"SLES15.0SP4"))) {
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
