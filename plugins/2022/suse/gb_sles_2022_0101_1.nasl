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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0101.1");
  script_cve_id("CVE-2021-22959", "CVE-2021-22960", "CVE-2021-37701", "CVE-2021-37712", "CVE-2021-37713", "CVE-2021-39134", "CVE-2021-39135", "CVE-2021-44531", "CVE-2021-44532", "CVE-2021-44533", "CVE-2022-21824");
  script_tag(name:"creation_date", value:"2022-01-20 07:39:58 +0000 (Thu, 20 Jan 2022)");
  script_version("2022-01-20T07:39:58+0000");
  script_tag(name:"last_modification", value:"2022-01-21 11:28:09 +0000 (Fri, 21 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-09 18:26:00 +0000 (Thu, 09 Sep 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0101-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0101-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220101-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs12' package(s) announced via the SUSE-SU-2022:0101-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs12 fixes the following issues:

CVE-2021-44531: Fixed improper handling of URI Subject Alternative Names
 (bsc#1194511).

CVE-2021-44532: Fixed certificate Verification Bypass via String
 Injection (bsc#1194512).

CVE-2021-44533: Fixed incorrect handling of certificate subject and
 issuer fields (bsc#1194513).

CVE-2022-21824: Fixed prototype pollution via console.table properties
 (bsc#1194514).

CVE-2021-22959: Fixed HTTP Request Smuggling due to spaced in
 headers(bsc#1191601).

CVE-2021-22960: Fixed HTTP Request Smuggling when parsing the body
 (bsc#1191602).

CVE-2021-37701: Fixed arbitrary file creation and overwrite
 vulnerability in nodejs-tar (bsc#1190057).

CVE-2021-37712: Fixed arbitrary file creation and overwrite
 vulnerability in nodejs-tar (bsc#1190056).

CVE-2021-37713: Fixed arbitrary file creation/overwrite and arbitrary
 code execution vulnerability in nodejs-tar (bsc#1190055).

CVE-2021-39134: Fixed symlink following vulnerability in nodejs-arborist
 (bsc#1190054).

CVE-2021-39135: Fixed symlink following vulnerability in nodejs-arborist
 (bsc#1190053).");

  script_tag(name:"affected", value:"'nodejs12' package(s) on SUSE Linux Enterprise Module for Web Scripting 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"nodejs12", rpm:"nodejs12~12.22.9~1.38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs12-debuginfo", rpm:"nodejs12-debuginfo~12.22.9~1.38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs12-debugsource", rpm:"nodejs12-debugsource~12.22.9~1.38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs12-devel", rpm:"nodejs12-devel~12.22.9~1.38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs12-docs", rpm:"nodejs12-docs~12.22.9~1.38.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm12", rpm:"npm12~12.22.9~1.38.1", rls:"SLES12.0"))) {
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
