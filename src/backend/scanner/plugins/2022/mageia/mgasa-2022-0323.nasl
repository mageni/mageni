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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0323");
  script_cve_id("CVE-2018-19351", "CVE-2018-21030", "CVE-2019-10255", "CVE-2019-10856", "CVE-2019-9644", "CVE-2020-26215", "CVE-2022-24758", "CVE-2022-24785", "CVE-2022-29238", "CVE-2022-31129");
  script_tag(name:"creation_date", value:"2022-09-12 05:06:20 +0000 (Mon, 12 Sep 2022)");
  script_version("2022-09-12T10:18:03+0000");
  script_tag(name:"last_modification", value:"2022-09-12 10:18:03 +0000 (Mon, 12 Sep 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-14 14:34:00 +0000 (Thu, 14 Jul 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0323)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0323");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0323.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30789");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30664");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5585-1");
  script_xref(name:"URL", value:"https://github.com/jupyter/notebook/security/advisories/GHSA-m87f-39q9-6f55");
  script_xref(name:"URL", value:"https://github.com/jupyter/notebook/security/advisories/GHSA-v7vq-3x77-87vg");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/ORJX2LF6KMPIHP6B2P6KZIVKMLE3LVJ5/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jupyter-notebook, python-nest-asyncio, python-send2trash' package(s) announced via the MGASA-2022-0323 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Jupyter Notebook incorrectly handled certain
notebooks. An attacker could possibly use this issue of lack of Content
Security Policy in Nbconvert to perform cross-site scripting (XSS) attacks
on the notebook server. (CVE-2018-19351)

It was discovered that Jupyter Notebook incorrectly handled certain SVG
documents. An attacker could possibly use this issue to perform cross-site
scripting (XSS) attacks. (CVE-2018-21030)

It was discovered that Jupyter Notebook incorrectly filtered certain URLs
on the login page. An attacker could possibly use this issue to perform
open-redirect attack. (CVE-2019-10255)

It was discovered that Jupyter Notebook had an incomplete fix for
CVE-2019-10255. An attacker could possibly use this issue to perform
open-redirect attack using empty netloc. (CVE-2019-10856)

It was discovered that Jupyter Notebook incorrectly handled the inclusion
of remote pages on Jupyter server. An attacker could possibly use this
issue to perform cross-site script inclusion (XSSI) attacks.
(CVE-2019-9644)

It was discovered that Jupyter Notebook incorrectly filtered certain URLs
to a notebook. An attacker could possibly use this issue to perform
open-redirect attack. (CVE-2020-26215)

It was discovered that Jupyter Notebook server access logs were not
protected. An attacker having access to the notebook server could possibly
use this issue to get access to steal sensitive information such as
auth/cookies. (CVE-2022-24758)

It was discovered that Jupyter Notebook incorrectly configured hidden
files on the server. An authenticated attacker could possibly use this
issue to see unwanted sensitive hidden files from the server which may
result in getting full access to the server. (CVE-2022-29238)

Moment.js: Path traversal in moment.locale (CVE-2022-24785)

moment: inefficient parsing algorithm resulting in DoS (CVE-2022-31129)");

  script_tag(name:"affected", value:"'jupyter-notebook, python-nest-asyncio, python-send2trash' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"jupyter-notebook", rpm:"jupyter-notebook~6.4.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-jupyter-notebook", rpm:"python-jupyter-notebook~6.4.12~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-nest-asyncio", rpm:"python-nest-asyncio~1.5.5~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-send2trash", rpm:"python-send2trash~1.8.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-nest-asyncio", rpm:"python3-nest-asyncio~1.5.5~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-send2trash", rpm:"python3-send2trash~1.8.0~1.mga8", rls:"MAGEIA8"))) {
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
