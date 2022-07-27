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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0343");
  script_cve_id("CVE-2018-4117", "CVE-2018-6044", "CVE-2018-6150", "CVE-2018-6151", "CVE-2018-6152", "CVE-2018-6153", "CVE-2018-6154", "CVE-2018-6155", "CVE-2018-6156", "CVE-2018-6157", "CVE-2018-6158", "CVE-2018-6159", "CVE-2018-6160", "CVE-2018-6161", "CVE-2018-6162", "CVE-2018-6163", "CVE-2018-6164", "CVE-2018-6165", "CVE-2018-6166", "CVE-2018-6167", "CVE-2018-6168", "CVE-2018-6169", "CVE-2018-6170", "CVE-2018-6171", "CVE-2018-6172", "CVE-2018-6173", "CVE-2018-6174", "CVE-2018-6175", "CVE-2018-6176", "CVE-2018-6177", "CVE-2018-6178", "CVE-2018-6179");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-05 20:39:00 +0000 (Tue, 05 Feb 2019)");

  script_name("Mageia: Security Advisory (MGASA-2018-0343)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0343");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0343.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23364");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/06/stable-channel-update-for-desktop_25.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/07/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/07/stable-channel-update-for-desktop_31.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/08/stable-channel-update-for-desktop.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2018-0343 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium-browser 68.0.3440.106 fixes security issues:

Multiple flaws were found in the way Chromium 67.0.3396.87 processes
various types of web content, where loading a web page containing
malicious content could cause Chromium to crash, execute arbitrary
code, or disclose sensitive information (CVE-2018-4117, CVE-2018-6044,
CVE-2018-6153, CVE-2018-6154, CVE-2018-6155, CVE-2018-6156, CVE-2018-6157,
CVE-2018-6158, CVE-2018-6159, CVE-2018-6160, CVE-2018-6161, CVE-2018-6162,
CVE-2018-6163, CVE-2018-6164, CVE-2018-6165, CVE-2018-6166, CVE-2018-6167,
CVE-2018-6168, CVE-2018-6169, CVE-2018-6170, CVE-2018-6171, CVE-2018-6172,
CVE-2018-6173, CVE-2018-6174, CVE-2018-6175, CVE-2018-6176, CVE-2018-6177,
CVE-2018-6178, CVE-2018-6179)

Upstream also reported for release 68.0.3440.75 that three additional
flaws were fixed in earlier (unspecified) chromium releases but not listed
in the release notes for those releases. (CVE-2018-6150, CVE-2018-6151,
CVE-2018-6152)");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~68.0.3440.106~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~68.0.3440.106~1.mga6", rls:"MAGEIA6"))) {
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
