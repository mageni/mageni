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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0234");
  script_cve_id("CVE-2013-2853", "CVE-2013-2867", "CVE-2013-2868", "CVE-2013-2869", "CVE-2013-2870", "CVE-2013-2871", "CVE-2013-2873", "CVE-2013-2875", "CVE-2013-2876", "CVE-2013-2878", "CVE-2013-2879", "CVE-2013-2880");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-19 01:36:00 +0000 (Tue, 19 Sep 2017)");

  script_name("Mageia: Security Advisory (MGASA-2013-0234)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(2|3)");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0234");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0234.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2013/07/stable-channel-update.html");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2724");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10804");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable, chromium-browser-stable, chromium-browser-stable' package(s) announced via the MGASA-2013-0234 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated chromium-browser-stable packages fix security vulnerabilities:

The HTTPS implementation does not ensure that headers are terminated by
\r\n\r\n (carriage return, newline, carriage return, newline)
(CVE-2013-2853).

Chrome does not properly prevent pop-under windows (CVE-2013-2867).

common/extensions/sync_helper.cc proceeds with sync operations for NPAPI
extensions without checking for a certain plugin permission setting
(CVE-2013-2868).

Denial of service (out-of-bounds read) via a crafted JPEG2000 image
(CVE-2013-2869).

Use-after-free vulnerability in network sockets (CVE-2013-2870).

Use-after-free vulnerability in input handling (CVE-2013-2871).

Use-after-free vulnerability in resource loading (CVE-2013-2873).

Out-of-bounds read in SVG file handling (CVE-2013-2875).

Chrome does not properly enforce restrictions on the capture of screenshots
by extensions, which could lead to information disclosure from previous page
visits (CVE-2013-2876).

Out-of-bounds read in text handling (CVE-2013-2878).

The circumstances in which a renderer process can be considered a trusted
process for sign-in and subsequent sync operations were not properly, property
checked (CVE-2013-2879).

The chrome 28 development team found various issues from internal fuzzing,
audits, and other studies (CVE-2013-2880).");

  script_tag(name:"affected", value:"'chromium-browser-stable, chromium-browser-stable, chromium-browser-stable' package(s) on Mageia 2, Mageia 3.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~28.0.1500.71~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~28.0.1500.71~1.mga2", rls:"MAGEIA2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~28.0.1500.71~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~28.0.1500.71~1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~28.0.1500.71~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~28.0.1500.71~1.mga3.tainted", rls:"MAGEIA3"))) {
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
