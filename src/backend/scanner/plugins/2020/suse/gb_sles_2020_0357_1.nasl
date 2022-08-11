# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0357.1");
  script_cve_id("CVE-2019-3695","CVE-2019-3696");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-04-19T13:49:56+0000");
  script_tag(name:"last_modification", value:"2021-04-20 10:28:26 +0000 (Tue, 20 Apr 2021)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-19 13:37:27 +0200 (Mon, 19 Apr 2021)");

  script_name("SUSE Linux Enterprise Server: Security Advisory (SUSE-SU-2020:0357-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0LTSS)");

  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-February/006470.html");

  script_tag(name:"summary", value:"The remote host is missing an update for 'pcp'
  package(s) announced via the SUSE-SU-2020:0357-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");

  script_tag(name:"affected", value:"'pcp' package(s) on SUSE Linux Enterprise Server 15");

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

if(release == "SLES15.0LTSS") {
  if(!isnull(res = isrpmvuln(pkg:"libpcp-devel", rpm:"libpcp-devel~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp3", rpm:"libpcp3~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp3-debuginfo", rpm:"libpcp3-debuginfo~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp_gui2", rpm:"libpcp_gui2~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp_gui2-debuginfo", rpm:"libpcp_gui2-debuginfo~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp_import1", rpm:"libpcp_import1~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp_import1-debuginfo", rpm:"libpcp_import1-debuginfo~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp_mmv1", rpm:"libpcp_mmv1~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp_mmv1-debuginfo", rpm:"libpcp_mmv1-debuginfo~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp_trace2", rpm:"libpcp_trace2~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp_trace2-debuginfo", rpm:"libpcp_trace2-debuginfo~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp_web1", rpm:"libpcp_web1~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcp_web1-debuginfo", rpm:"libpcp_web1-debuginfo~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp", rpm:"pcp~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-conf", rpm:"pcp-conf~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-debuginfo", rpm:"pcp-debuginfo~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-debugsource", rpm:"pcp-debugsource~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-devel", rpm:"pcp-devel~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-devel-debuginfo", rpm:"pcp-devel-debuginfo~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-import-iostat2pcp", rpm:"pcp-import-iostat2pcp~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-import-mrtg2pcp", rpm:"pcp-import-mrtg2pcp~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-import-sar2pcp", rpm:"pcp-import-sar2pcp~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PCP-LogImport", rpm:"perl-PCP-LogImport~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PCP-LogImport-debuginfo", rpm:"perl-PCP-LogImport-debuginfo~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PCP-LogSummary", rpm:"perl-PCP-LogSummary~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PCP-MMV", rpm:"perl-PCP-MMV~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PCP-MMV-debuginfo", rpm:"perl-PCP-MMV-debuginfo~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PCP-PMDA", rpm:"perl-PCP-PMDA~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PCP-PMDA-debuginfo", rpm:"perl-PCP-PMDA-debuginfo~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pcp", rpm:"python-pcp~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pcp-debuginfo", rpm:"python-pcp-debuginfo~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-doc", rpm:"pcp-doc~3.11.9~5.8.1", rls:"SLES15.0LTSS"))){
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
