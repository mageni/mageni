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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0185.1");
  script_cve_id("CVE-2006-20001", "CVE-2022-36760", "CVE-2022-37436");
  script_tag(name:"creation_date", value:"2023-01-30 04:19:32 +0000 (Mon, 30 Jan 2023)");
  script_version("2023-02-01T10:08:40+0000");
  script_tag(name:"last_modification", value:"2023-02-01 10:08:40 +0000 (Wed, 01 Feb 2023)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-30 19:21:00 +0000 (Mon, 30 Jan 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0185-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0185-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230185-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the SUSE-SU-2023:0185-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apache2 fixes the following issues:

CVE-2022-37436: Fixed an issue in mod_proxy where a malicious backend
 could cause the response headers to be truncated early, resulting in
 some headers being incorporated into the response body (bsc#1207251).

CVE-2022-36760: Fixed an issue in mod_proxy_ajp that could allow request
 smuggling attacks (bsc#1207250).

CVE-2006-20001: Fixed an issue in mod_proxy_ajp where a request header
 could cause memory corruption (bsc#1207247).");

  script_tag(name:"affected", value:"'apache2' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"apache2", rpm:"apache2~2.4.51~35.22.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-debuginfo", rpm:"apache2-debuginfo~2.4.51~35.22.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-debugsource", rpm:"apache2-debugsource~2.4.51~35.22.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-doc", rpm:"apache2-doc~2.4.51~35.22.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-example-pages", rpm:"apache2-example-pages~2.4.51~35.22.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-prefork", rpm:"apache2-prefork~2.4.51~35.22.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-prefork-debuginfo", rpm:"apache2-prefork-debuginfo~2.4.51~35.22.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-utils", rpm:"apache2-utils~2.4.51~35.22.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-utils-debuginfo", rpm:"apache2-utils-debuginfo~2.4.51~35.22.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-worker", rpm:"apache2-worker~2.4.51~35.22.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-worker-debuginfo", rpm:"apache2-worker-debuginfo~2.4.51~35.22.1", rls:"SLES12.0SP5"))) {
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
