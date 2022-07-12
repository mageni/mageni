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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0194");
  script_cve_id("CVE-2013-2837", "CVE-2013-2838", "CVE-2013-2839", "CVE-2013-2840", "CVE-2013-2841", "CVE-2013-2842", "CVE-2013-2843", "CVE-2013-2844", "CVE-2013-2845", "CVE-2013-2846", "CVE-2013-2847", "CVE-2013-2848", "CVE-2013-2849", "CVE-2013-2855", "CVE-2013-2856", "CVE-2013-2857", "CVE-2013-2858", "CVE-2013-2859", "CVE-2013-2860", "CVE-2013-2861", "CVE-2013-2862", "CVE-2013-2863", "CVE-2013-2865");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-19 01:36:00 +0000 (Tue, 19 Sep 2017)");

  script_name("Mageia: Security Advisory (MGASA-2013-0194)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(2|3)");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0194");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0194.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10353");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2013/05/stable-channel-release.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2013/06/stable-channel-update.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2013/06/stable-channel-update_17.html");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2695");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2706");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable, chromium-browser-stable' package(s) announced via the MGASA-2013-0194 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Use-after-free vulnerability in the SVG implementation allows remote
attackers to cause a denial of service or possibly have unspecified other
impact via unknown vectors (CVE-2013-2837).

Google V8, as used in Chromium before 27.0.1453.93, allows remote attackers
to cause a denial of service (out-of-bounds read) via unspecified vectors
(CVE-2013-2838).

Chromium before 27.0.1453.93 does not properly perform a cast of an
unspecified variable during handling of clipboard data, which allows remote
attackers to cause a denial of service or possibly have other impact via
unknown vectors (CVE-2013-2839).

Use-after-free vulnerability in the media loader in Chromium before
27.0.1453.93 allows remote attackers to cause a denial of service or possibly
have unspecified other impact via unknown vectors (CVE-2013-2840).

Use-after-free vulnerability in Chromium before 27.0.1453.93 allows remote
attackers to cause a denial of service or possibly have unspecified other
impact via vectors related to the handling of Pepper resources
(CVE-2013-2841).

Use-after-free vulnerability in Chromium before 27.0.1453.93 allows remote
attackers to cause a denial of service or possibly have unspecified other
impact via vectors related to the handling of widgets (CVE-2013-2842).

Use-after-free vulnerability in Chromium before 27.0.1453.93 allows remote
attackers to cause a denial of service or possibly have unspecified other
impact via vectors related to the handling of speech data (CVE-2013-2843).

Use-after-free vulnerability in the Cascading Style Sheets (CSS)
implementation in Chromium before 27.0.1453.93 allows remote attackers to
cause a denial of service or possibly have unspecified other impact via
vectors related to style resolution (CVE-2013-2844).

The Web Audio implementation in Google Chrome before 27.0.1453.93 allows
remote attackers to cause a denial of service (memory corruption) or possibly
have unspecified other impact via unknown vectors (CVE-2013-2845).

Use-after-free vulnerability in the media loader in Google Chrome before
27.0.1453.93 allows remote attackers to cause a denial of service or possibly
have unspecified other impact via unknown vectors (CVE-2013-2846).

Race condition in the workers implementation in Google Chrome before
27.0.1453.93 allows remote attackers to cause a denial of service
(use-after-free and application crash) or possibly have unspecified other
impact via unknown vectors (CVE-2013-2847).

The XSS Auditor in Google Chrome before 27.0.1453.93 might allow remote
attackers to obtain sensitive information via unspecified vectors
(CVE-2013-2848).

Multiple cross-site scripting (XSS) vulnerabilities in Google Chrome before
27.0.1453.93 allow user-assisted remote attackers to inject arbitrary web
script or HTML via vectors involving a (1) drag-and-drop or
(2) copy-and-paste operation (CVE-2013-2849).

The Developer Tools API in Chromium before 27.0.1453.110 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'chromium-browser-stable, chromium-browser-stable' package(s) on Mageia 2, Mageia 3.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~28.0.1500.45~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~28.0.1500.45~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~28.0.1500.45~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~28.0.1500.45~1.mga3", rls:"MAGEIA3"))) {
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
