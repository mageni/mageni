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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0317");
  script_cve_id("CVE-2017-5059", "CVE-2017-5060", "CVE-2017-5061", "CVE-2017-5062", "CVE-2017-5063", "CVE-2017-5064", "CVE-2017-5065", "CVE-2017-5066", "CVE-2017-5067", "CVE-2017-5068", "CVE-2017-5069", "CVE-2017-5070", "CVE-2017-5071", "CVE-2017-5072", "CVE-2017-5073", "CVE-2017-5074", "CVE-2017-5075", "CVE-2017-5076", "CVE-2017-5077", "CVE-2017-5078", "CVE-2017-5079", "CVE-2017-5080", "CVE-2017-5081", "CVE-2017-5082", "CVE-2017-5083", "CVE-2017-5085", "CVE-2017-5086", "CVE-2017-5087", "CVE-2017-5088", "CVE-2017-5089", "CVE-2017-5091", "CVE-2017-5092", "CVE-2017-5093", "CVE-2017-5094", "CVE-2017-5095", "CVE-2017-5096", "CVE-2017-5097", "CVE-2017-5098", "CVE-2017-5099", "CVE-2017-5100", "CVE-2017-5101", "CVE-2017-5102", "CVE-2017-5103", "CVE-2017-5104", "CVE-2017-5105", "CVE-2017-5106", "CVE-2017-5107", "CVE-2017-5108", "CVE-2017-5109", "CVE-2017-5110", "CVE-2017-6991");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Mageia: Security Advisory (MGASA-2017-0317)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0317");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0317.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20708");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/04/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/05/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/05/stable-channel-update-for-desktop_9.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/06/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/06/stable-channel-update-for-desktop_15.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/06/stable-channel-update-for-desktop_20.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/06/stable-channel-update-for-desktop_26.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/07/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/08/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/08/stable-channel-update-for-desktop_14.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable, chromium-browser-stable, libwebp' package(s) announced via the MGASA-2017-0317 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws were found in the way Chromium 57 processes various types
of web content, where loading a web page containing malicious content
could cause Chromium to crash, execute arbitrary code, or disclose
sensitive information. (CVE-2017-5057, CVE-2017-5058, CVE-2017-5059,
CVE-2017-5060, CVE-2017-5061, CVE-2017-5062, CVE-2017-5063,
CVE-2017-5064, CVE-2017-5065, CVE-2017-5066, CVE-2017-5067,
CVE-2017-5068, CVE-2017-5069, CVE-2017-5070, CVE-2017-5071,
CVE-2017-5072, CVE-2017-5073, CVE-2017-5074, CVE-2017-5075,
CVE-2017-5076, CVE-2017-5077, CVE-2017-5078, CVE-2017-5079,
CVE-2017-5080, CVE-2017-5081, CVE-2017-5082, CVE-2017-5083,
CVE-2017-5085, CVE-2017-5086, CVE-2017-5087, CVE-2017-5088,
CVE-2017-5089, CVE-2017-5091, CVE-2017-5092, CVE-2017-5093,
CVE-2017-5094, CVE-2017-5095, CVE-2017-5096, CVE-2017-5097,
CVE-2017-5098, CVE-2017-5099, CVE-2017-5100, CVE-2017-5101,
CVE-2017-5102, CVE-2017-5103, CVE-2017-5104, CVE-2017-5105,
CVE-2017-5106, CVE-2017-5107, CVE-2017-5108, CVE-2017-5109,
CVE-2017-5110, CVE-2017-6991)");

  script_tag(name:"affected", value:"'chromium-browser-stable, chromium-browser-stable, libwebp' package(s) on Mageia 5, Mageia 6.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~60.0.3112.101~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~60.0.3112.101~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webp-devel", rpm:"lib64webp-devel~0.4.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webp5", rpm:"lib64webp5~0.4.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webpdecoder1", rpm:"lib64webpdecoder1~0.4.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webpdemux1", rpm:"lib64webpdemux1~0.4.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webpmux1", rpm:"lib64webpmux1~0.4.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp", rpm:"libwebp~0.4.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-devel", rpm:"libwebp-devel~0.4.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-tools", rpm:"libwebp-tools~0.4.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp5", rpm:"libwebp5~0.4.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdecoder1", rpm:"libwebpdecoder1~0.4.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpdemux1", rpm:"libwebpdemux1~0.4.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebpmux1", rpm:"libwebpmux1~0.4.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~60.0.3112.101~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~60.0.3112.101~1.mga6", rls:"MAGEIA6"))) {
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
