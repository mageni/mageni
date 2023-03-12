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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0429.1");
  script_cve_id("CVE-2023-23914", "CVE-2023-23915", "CVE-2023-23916");
  script_tag(name:"creation_date", value:"2023-02-16 04:21:52 +0000 (Thu, 16 Feb 2023)");
  script_version("2023-03-06T10:10:02+0000");
  script_tag(name:"last_modification", value:"2023-03-06 10:10:02 +0000 (Mon, 06 Mar 2023)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-03 16:08:00 +0000 (Fri, 03 Mar 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0429-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0429-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230429-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the SUSE-SU-2023:0429-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for curl fixes the following issues:

CVE-2023-23914: Fixed HSTS ignored on multiple requests (bsc#1207990).

CVE-2023-23915: Fixed HSTS amnesia with --parallel (bsc#1207991).

CVE-2023-23916: Fixed HTTP multi-header compression denial of service
 (bsc#1207992).");

  script_tag(name:"affected", value:"'curl' package(s) on SUSE Linux Enterprise Micro 5.3, SUSE Linux Enterprise Module for Basesystem 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.79.1~150400.5.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"curl-debuginfo", rpm:"curl-debuginfo~7.79.1~150400.5.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"curl-debugsource", rpm:"curl-debugsource~7.79.1~150400.5.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.79.1~150400.5.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4-32bit", rpm:"libcurl4-32bit~7.79.1~150400.5.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4-32bit-debuginfo", rpm:"libcurl4-32bit-debuginfo~7.79.1~150400.5.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4", rpm:"libcurl4~7.79.1~150400.5.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4-debuginfo", rpm:"libcurl4-debuginfo~7.79.1~150400.5.15.1", rls:"SLES15.0SP4"))) {
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
