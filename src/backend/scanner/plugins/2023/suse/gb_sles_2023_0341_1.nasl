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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0341.1");
  script_cve_id("CVE-2022-3094", "CVE-2022-3736", "CVE-2022-3924");
  script_tag(name:"creation_date", value:"2023-02-13 04:19:57 +0000 (Mon, 13 Feb 2023)");
  script_version("2023-02-13T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-02-13 10:09:19 +0000 (Mon, 13 Feb 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-06 16:28:00 +0000 (Mon, 06 Feb 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0341-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0341-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230341-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind' package(s) announced via the SUSE-SU-2023:0341-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for bind fixes the following issues:

Updated to version 9.16.37 (jsc#SLE-24600):
 - CVE-2022-3094: Fixed an issue where a message flood could exhaust all
 available memory (bsc#1207471).
 - CVE-2022-3736: Fixed a potential crash upon receiving an RRSIG in
 configurations with stale cache and stale answers enabled and
 stale-answer-client-timeout set to a positive value (bsc#1207473).
 - CVE-2022-3924: Fixed a potential crash upon reaching the
 recursive-clients soft quota in configurations with stale answers
 enabled and stale-answer-client-timeout set to a positive value
 (bsc#1207475).");

  script_tag(name:"affected", value:"'bind' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP4, SUSE Linux Enterprise Module for Server Applications 15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.16.37~150400.5.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debugsource", rpm:"bind-debugsource~9.16.37~150400.5.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.16.37~150400.5.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils-debuginfo", rpm:"bind-utils-debuginfo~9.16.37~150400.5.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-bind", rpm:"python3-bind~9.16.37~150400.5.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.16.37~150400.5.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.16.37~150400.5.17.1", rls:"SLES15.0SP4"))) {
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
