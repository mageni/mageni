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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0294");
  script_cve_id("CVE-2021-43616", "CVE-2022-32212", "CVE-2022-32213", "CVE-2022-32214", "CVE-2022-32215", "CVE-2022-32222");
  script_tag(name:"creation_date", value:"2022-08-26 04:58:48 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T04:58:48+0000");
  script_tag(name:"last_modification", value:"2022-08-26 04:58:48 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-17 19:56:00 +0000 (Wed, 17 Nov 2021)");

  script_name("Mageia: Security Advisory (MGASA-2022-0294)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0294");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0294.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30078");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/july-2022-security-releases/");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/releases/tag/v14.19.0");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/releases/tag/v14.19.1");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/releases/tag/v14.19.2");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/releases/tag/v14.19.3");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/releases/tag/v14.20.0");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs' package(s) announced via the MGASA-2022-0294 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The npm ci command in npm 7.x and 8.x through 8.1.3 proceeds with an
installation even if dependency information in package-lock.json differs
from package.json. This behavior is inconsistent with the documentation,
and makes it easier for attackers to install malware that was supposed to
have been blocked by an exact version match requirement in
package-lock.json. (CVE-2021-43616)

DNS rebinding in --inspect via invalid IP addresses (CVE-2022-32212)

HTTP Request Smuggling - Flawed Parsing of Transfer-Encoding
(CVE-2022-32213)

HTTP Request Smuggling - Improper Delimiting of Header Fields
(CVE-2022-32214)

HTTP Request Smuggling - Incorrect Parsing of Multi-line Transfer-Encoding
(CVE-2022-32215)

Attempt to read openssl.cnf from /home/iojs/build/ upon startup
(CVE-2022-32222)");

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

  if(!isnull(res = isrpmvuln(pkg:"corepack", rpm:"corepack~14.20.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs", rpm:"nodejs~14.20.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-devel", rpm:"nodejs-devel~14.20.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-docs", rpm:"nodejs-docs~14.20.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-libs", rpm:"nodejs-libs~14.20.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm", rpm:"npm~6.14.17~1.14.20.0.1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v8-devel", rpm:"v8-devel~8.4.371.23.1.mga8~4.1.mga8", rls:"MAGEIA8"))) {
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
