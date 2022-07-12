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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0372");
  script_cve_id("CVE-2020-7774", "CVE-2021-23362", "CVE-2021-27290");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-09 13:27:00 +0000 (Fri, 09 Apr 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0372)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0372");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0372.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29028");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v14.17.0/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v14.17.1/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v14.17.2/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v14.17.3/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/july-2021-security-releases/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/april-2021-security-releases/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v14.16.1/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/TE6GHYMCD4SLCPTFPANLIYWCPHXC4G5T/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs' package(s) announced via the MGASA-2021-0372 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This affects the package y18n before 3.2.2, 4.0.1 and 5.0.5. PoC by po6ix:
const y18n = require('y18n')(),
y18n.setLocale('__proto__'), y18n.updateLocale({polluted: true}),
console.log(polluted), // true (CVE-2020-7774).

The package hosted-git-info before 3.0.8 are vulnerable to Regular Expression
Denial of Service (ReDoS) via regular expression shortcutMatch in the fromUrl
function in index.js. The affected regular expression exhibits polynomial
worst-case time complexity (CVE-2021-23362).

ssri 5.2.2-8.0.0, fixed in 8.0.1, processes SRIs using a regular expression
which is vulnerable to a denial of service. Malicious SRIs could take an
extremely long time to process, leading to denial of service. This issue only
affects consumers using the strict option (CVE-2021-27290).

These, thesis issues are fixed by upgrading nodejs packages to latest available
LTS 14.17.3 version. See upstream releases notes for other included bugfixes.");

  script_tag(name:"affected", value:"'nodejs' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs", rpm:"nodejs~14.17.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-devel", rpm:"nodejs-devel~14.17.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-docs", rpm:"nodejs-docs~14.17.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-libs", rpm:"nodejs-libs~14.17.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm", rpm:"npm~6.14.13~1.14.17.3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v8-devel", rpm:"v8-devel~8.4.371.23.mga8~1.mga8", rls:"MAGEIA8"))) {
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
