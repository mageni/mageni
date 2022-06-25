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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0570.1");
  script_cve_id("CVE-2021-23343", "CVE-2021-32803", "CVE-2021-32804", "CVE-2021-3807", "CVE-2021-3918", "CVE-2022-21824");
  script_tag(name:"creation_date", value:"2022-02-25 03:26:49 +0000 (Fri, 25 Feb 2022)");
  script_version("2022-02-25T03:26:49+0000");
  script_tag(name:"last_modification", value:"2022-02-25 03:26:49 +0000 (Fri, 25 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-16 18:46:00 +0000 (Tue, 16 Nov 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0570-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0570-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220570-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs10' package(s) announced via the SUSE-SU-2022:0570-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs10 fixes the following issues:

CVE-2021-23343: Fixed ReDoS via splitDeviceRe, splitTailRe and
 splitPathRe (bsc#1192153).

CVE-2021-32803: Fixed insufficient symlink protection in node-tar
 allowing arbitrary file creation and overwrite (bsc#1191963).

CVE-2021-32804: Fixed insufficient absolute path sanitization in
 node-tar allowing arbitrary file creation and overwrite (bsc#1191962).

CVE-2021-3918: Fixed improper controlled modification of object
 prototype attributes in json-schema (bsc#1192696).

CVE-2021-3807: Fixed regular expression denial of service (ReDoS)
 matching ANSI escape codes in node-ansi-regex (bsc#1192154).

CVE-2022-21824: Fixed prototype pollution via console.table
 (bsc#1194514).");

  script_tag(name:"affected", value:"'nodejs10' package(s) on SUSE Linux Enterprise Module for Web Scripting 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs10", rpm:"nodejs10~10.24.1~1.46.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-debuginfo", rpm:"nodejs10-debuginfo~10.24.1~1.46.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-debugsource", rpm:"nodejs10-debugsource~10.24.1~1.46.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-devel", rpm:"nodejs10-devel~10.24.1~1.46.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-docs", rpm:"nodejs10-docs~10.24.1~1.46.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm10", rpm:"npm10~10.24.1~1.46.1", rls:"SLES12.0"))) {
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
