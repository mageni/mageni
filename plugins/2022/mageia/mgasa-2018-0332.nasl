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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0332");
  script_cve_id("CVE-2017-12081", "CVE-2017-12082", "CVE-2017-12086", "CVE-2017-12099", "CVE-2017-12100", "CVE-2017-12101", "CVE-2017-12102", "CVE-2017-12103", "CVE-2017-12104", "CVE-2017-12105", "CVE-2017-2899", "CVE-2017-2900", "CVE-2017-2901", "CVE-2017-2902", "CVE-2017-2903", "CVE-2017-2904", "CVE-2017-2905", "CVE-2017-2906", "CVE-2017-2907", "CVE-2017-2908", "CVE-2017-2918");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-26 19:24:00 +0000 (Tue, 26 Mar 2019)");

  script_name("Mageia: Security Advisory (MGASA-2018-0332)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0332");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0332.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23332");
  script_xref(name:"URL", value:"https://www.blender.org/features/2-79/");
  script_xref(name:"URL", value:"http://www.yafaray.org/node/817");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4248");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'blender, yafaray' package(s) announced via the MGASA-2018-0332 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated blender package fixes security vulnerabilities:

Multiple vulnerabilities have been discovered in various parsers of Blender.
Malformed .blend model files and malformed multimedia files (AVI, BMP, HDR,
CIN, IRIS, PNG, TIFF) may result in the execution of arbitrary code
(CVE-2017-2899, CVE-2017-2900, CVE-2017-2901, CVE-2017-2902, CVE-2017-2903,
 CVE-2017-2904, CVE-2017-2905, CVE-2017-2906, CVE-2017-2907, CVE-2017-2908,
 CVE-2017-2918, CVE-2017-12081, CVE-2017-12082, CVE-2017-12086,
 CVE-2017-12099, CVE-2017-12100, CVE-2017-12101, CVE-2017-12102,
 CVE-2017-12103, CVE-2017-12104, CVE-2017-12105).

These issues are fixed by updating to the latest upstream 2.79b release,
which brings many improvements, bug fixes and new features. See the
referenced changelog for details.

Also, the yafaray package has been updated to the latest version, 3.3.0, to
make it work with the new Blender addons path.");

  script_tag(name:"affected", value:"'blender, yafaray' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"blender", rpm:"blender~2.79b~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yafaray", rpm:"yafaray~3.3.0~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yafaray-blender", rpm:"yafaray-blender~3.3.0~1.2.mga6", rls:"MAGEIA6"))) {
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
