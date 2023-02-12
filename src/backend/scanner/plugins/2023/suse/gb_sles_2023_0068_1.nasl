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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0068.1");
  script_cve_id("CVE-2022-44792", "CVE-2022-44793");
  script_tag(name:"creation_date", value:"2023-01-12 04:19:12 +0000 (Thu, 12 Jan 2023)");
  script_version("2023-01-12T10:12:15+0000");
  script_tag(name:"last_modification", value:"2023-01-12 10:12:15 +0000 (Thu, 12 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-08 04:23:00 +0000 (Tue, 08 Nov 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0068-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0068-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230068-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-snmp' package(s) announced via the SUSE-SU-2023:0068-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for net-snmp fixes the following issues:

CVE-2022-44793: Fixed a NULL pointer dereference issue that could allow
 a remote attacker with write access to crash the server instance
 (bsc#1205148).

CVE-2022-44792: Fixed a NULL pointer dereference issue that could allow
 a remote attacker with write access to crash the server instance
 (bsc#1205150).

Other fixes:
Fixed a potential invalid free of memory, and hardened string handling
 against concurrency issues (bsc#1198059).");

  script_tag(name:"affected", value:"'net-snmp' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libsnmp30-32bit", rpm:"libsnmp30-32bit~5.7.3~11.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsnmp30", rpm:"libsnmp30~5.7.3~11.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsnmp30-debuginfo-32bit", rpm:"libsnmp30-debuginfo-32bit~5.7.3~11.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsnmp30-debuginfo", rpm:"libsnmp30-debuginfo~5.7.3~11.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.7.3~11.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-debuginfo", rpm:"net-snmp-debuginfo~5.7.3~11.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-debugsource", rpm:"net-snmp-debugsource~5.7.3~11.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.7.3~11.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-SNMP-debuginfo", rpm:"perl-SNMP-debuginfo~5.7.3~11.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snmp-mibs", rpm:"snmp-mibs~5.7.3~11.6.1", rls:"SLES12.0SP5"))) {
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
