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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0383");
  script_cve_id("CVE-2013-6632", "CVE-2013-6634", "CVE-2013-6635", "CVE-2013-6636", "CVE-2013-6637", "CVE-2013-6638", "CVE-2013-6639", "CVE-2013-6640");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-13 17:58:00 +0000 (Thu, 13 Dec 2018)");

  script_name("Mageia: Security Advisory (MGASA-2013-0383)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0383");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0383.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2013/11/stable-channel-update_14.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2013/12/stable-channel-update.html");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2799");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2811");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11935");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable, chromium-browser-stable' package(s) announced via the MGASA-2013-0383 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated chromium-browser-stable packages fix security vulnerabilities:

Pinkie Pie discovered multiple memory corruption issues (CVE-2013-6632).

Andrey Labunets discovered that the wrong URL was used during validation in
the one-click sign on helper (CVE-2013-6634).

cloudfuzzer discovered use-after-free issues in the InsertHTML and Indent DOM
editing commands (CVE-2013-6635).

Bas Venis discovered an address bar spoofing issue (CVE-2013-6636).

The chrome 31 development team discovered and fixed multiple issues with
potential security impact (CVE-2013-6637).

Jakob Kummerow of the Chromium project discovered a buffer overflow in the v8
javascript library (CVE-2013-6638).

Jakob Kummerow of the Chromium project discovered an out-of-bounds write in
the v8 javascript library (CVE-2013-6639).

Jakob Kummerow of the Chromium project discovered an out-of-bounds read in
the v8 javascript library (CVE-2013-6640).");

  script_tag(name:"affected", value:"'chromium-browser-stable, chromium-browser-stable' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~31.0.1650.63~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~31.0.1650.63~1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~31.0.1650.63~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~31.0.1650.63~1.mga3.tainted", rls:"MAGEIA3"))) {
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
