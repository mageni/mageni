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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0944.2");
  script_cve_id("CVE-2017-5601", "CVE-2021-36976");
  script_tag(name:"creation_date", value:"2023-02-01 04:23:10 +0000 (Wed, 01 Feb 2023)");
  script_version("2023-02-01T10:08:40+0000");
  script_tag(name:"last_modification", value:"2023-02-01 10:08:40 +0000 (Wed, 01 Feb 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-30 11:29:00 +0000 (Fri, 30 Nov 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0944-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0944-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220944-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libarchive' package(s) announced via the SUSE-SU-2022:0944-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libarchive fixes the following issues:

CVE-2021-36976: Fixed an invalid memory access that could cause data
 corruption (bsc#1188572).

Non-security updates:

Updated references for CVE-2017-5601, which was already fixed in a
 previous version (bsc#1022528 bsc#1189528).");

  script_tag(name:"affected", value:"'libarchive' package(s) on SUSE Enterprise Storage 7, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"bsdtar", rpm:"bsdtar~3.4.2~150200.4.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bsdtar-debuginfo", rpm:"bsdtar-debuginfo~3.4.2~150200.4.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive-debugsource", rpm:"libarchive-debugsource~3.4.2~150200.4.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive-devel", rpm:"libarchive-devel~3.4.2~150200.4.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive13", rpm:"libarchive13~3.4.2~150200.4.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive13-debuginfo", rpm:"libarchive13-debuginfo~3.4.2~150200.4.3.1", rls:"SLES15.0SP2"))) {
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
