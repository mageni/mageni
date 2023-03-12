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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0362.1");
  script_cve_id("CVE-2022-31123", "CVE-2022-31130", "CVE-2022-39201", "CVE-2022-39229", "CVE-2022-39306", "CVE-2022-39307");
  script_tag(name:"creation_date", value:"2023-02-13 04:19:57 +0000 (Mon, 13 Feb 2023)");
  script_version("2023-02-13T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-02-13 10:09:19 +0000 (Mon, 13 Feb 2023)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-14 18:54:00 +0000 (Mon, 14 Nov 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0362-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0362-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230362-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grafana' package(s) announced via the SUSE-SU-2023:0362-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for grafana fixes the following issues:

Version update from 8.5.13 to 8.5.15 (jsc#PED-2617):
 * CVE-2022-39306: Security fix for privilege escalation (bsc#1205225)
 * CVE-2022-39307: Omit error from http response when user does not
 exists (bsc#1205227)
 * CVE-2022-39201: Do not forward login cookie in outgoing requests
 (bsc#1204303)
 * CVE-2022-31130: Make proxy endpoints not leak sensitive HTTP headers
 (bsc#1204305)
 * CVE-2022-31123: Fix plugin signature bypass (bsc#1204302)
 * CVE-2022-39229: Fix blocking other users from signing in (bsc#1204304)");

  script_tag(name:"affected", value:"'grafana' package(s) on SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"grafana", rpm:"grafana~8.5.15~150200.3.32.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grafana-debuginfo", rpm:"grafana-debuginfo~8.5.15~150200.3.32.1", rls:"SLES15.0SP4"))) {
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
