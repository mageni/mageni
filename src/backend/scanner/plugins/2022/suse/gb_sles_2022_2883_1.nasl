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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2883.1");
  script_cve_id("CVE-2022-0204");
  script_tag(name:"creation_date", value:"2022-08-25 04:49:54 +0000 (Thu, 25 Aug 2022)");
  script_version("2022-08-25T04:49:54+0000");
  script_tag(name:"last_modification", value:"2022-08-25 04:49:54 +0000 (Thu, 25 Aug 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-16 14:54:00 +0000 (Wed, 16 Mar 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2883-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2883-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222883-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bluez' package(s) announced via the SUSE-SU-2022:2883-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for bluez fixes the following issues:

CVE-2022-0204: Fixed a buffer overflow in the implementation of the gatt
 protocol (bsc#1194704).");

  script_tag(name:"affected", value:"'bluez' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Desktop Applications 15-SP3, SUSE Linux Enterprise Workstation Extension 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"bluez", rpm:"bluez~5.55~150300.3.11.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-debuginfo", rpm:"bluez-debuginfo~5.55~150300.3.11.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-debugsource", rpm:"bluez-debugsource~5.55~150300.3.11.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-deprecated", rpm:"bluez-deprecated~5.55~150300.3.11.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-deprecated-debuginfo", rpm:"bluez-deprecated-debuginfo~5.55~150300.3.11.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbluetooth3", rpm:"libbluetooth3~5.55~150300.3.11.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbluetooth3-debuginfo", rpm:"libbluetooth3-debuginfo~5.55~150300.3.11.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-devel", rpm:"bluez-devel~5.55~150300.3.11.1", rls:"SLES15.0SP3"))) {
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
