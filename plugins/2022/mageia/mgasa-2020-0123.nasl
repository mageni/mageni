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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0123");
  script_cve_id("CVE-2019-1819", "CVE-2019-19923", "CVE-2019-19925", "CVE-2019-19926", "CVE-2020-6381", "CVE-2020-6382", "CVE-2020-6383", "CVE-2020-6384", "CVE-2020-6385", "CVE-2020-6386", "CVE-2020-6387", "CVE-2020-6388", "CVE-2020-6389", "CVE-2020-6390", "CVE-2020-6391", "CVE-2020-6392", "CVE-2020-6393", "CVE-2020-6394", "CVE-2020-6395", "CVE-2020-6396", "CVE-2020-6397", "CVE-2020-6398", "CVE-2020-6399", "CVE-2020-6400", "CVE-2020-6401", "CVE-2020-6402", "CVE-2020-6403", "CVE-2020-6404", "CVE-2020-6405", "CVE-2020-6406", "CVE-2020-6407", "CVE-2020-6408", "CVE-2020-6409", "CVE-2020-6410", "CVE-2020-6411", "CVE-2020-6412", "CVE-2020-6413", "CVE-2020-6414", "CVE-2020-6415", "CVE-2020-6416", "CVE-2020-6418");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-17 12:15:00 +0000 (Mon, 17 Feb 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0123)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0123");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0123.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26269");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2020/02/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2020/02/stable-channel-update-for-desktop_11.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2020/02/stable-channel-update-for-desktop_13.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2020/02/stable-channel-update-for-desktop_18.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2020/02/stable-channel-update-for-desktop_24.html");
  script_xref(name:"URL", value:"https://unicode-org.atlassian.net/browse/ICU-20958");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable, icu' package(s) announced via the MGASA-2020-0123 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium-browser 80.0.3987.122 fixes security issues:

Multiple flaws were found in the way Chromium 79.0.3945.130 processes
various types of web content, where loading a web page containing malicious
content could cause Chromium to crash, execute arbitrary code, or disclose
sensitive information. (CVE-2020-6381, CVE-2020-6382, CVE-2020-6383,
CVE-2020-6384, CVE-2020-6385, CVE-2020-6386, CVE-2020-6387, CVE-2020-6388,
CVE-2020-6389, CVE-2020-6390, CVE-2020-6391, CVE-2020-6392, CVE-2020-6393,
CVE-2020-6394, CVE-2020-6395, CVE-2020-6396, CVE-2020-6397, CVE-2020-6398,
CVE-2020-6399, CVE-2020-6400, CVE-2020-6401, CVE-2020-6402, CVE-2020-6403,
CVE-2020-6404, CVE-2020-6405, CVE-2020-6406, CVE-2020-6407, CVE-2020-6408,
CVE-2020-6409, CVE-2020-6410, CVE-2020-6411, CVE-2020-6412, CVE-2020-6413,
CVE-2020-6414, CVE-2020-6415, CVE-2020-6416, CVE-2020-6418, CVE-2019-18197,
CVE-2019-19923, CVE-2019-19925, CVE-2019-19926)

Upstream chromium 80.0.3987.122 also includes a fix for an integer overflow
issue in ICU. Since the chromium-browser-stable package is linked against
the icu packages instead of using the ICU source code bundled with chromium
upstream, this issue is fixed in the icu package.");

  script_tag(name:"affected", value:"'chromium-browser-stable, icu' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~80.0.3987.122~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~80.0.3987.122~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icu", rpm:"icu~63.1~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icu-doc", rpm:"icu-doc~63.1~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icu63-data", rpm:"icu63-data~63.1~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64icu-devel", rpm:"lib64icu-devel~63.1~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64icu63", rpm:"lib64icu63~63.1~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu-devel", rpm:"libicu-devel~63.1~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu63", rpm:"libicu63~63.1~1.2.mga7", rls:"MAGEIA7"))) {
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
