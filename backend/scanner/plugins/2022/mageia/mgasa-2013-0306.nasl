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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0306");
  script_cve_id("CVE-2013-2906", "CVE-2013-2907", "CVE-2013-2908", "CVE-2013-2909", "CVE-2013-2910", "CVE-2013-2911", "CVE-2013-2912", "CVE-2013-2913", "CVE-2013-2914", "CVE-2013-2915", "CVE-2013-2916", "CVE-2013-2917", "CVE-2013-2918", "CVE-2013-2919", "CVE-2013-2920", "CVE-2013-2921", "CVE-2013-2922", "CVE-2013-2923", "CVE-2013-2924");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-19 01:36:00 +0000 (Tue, 19 Sep 2017)");

  script_name("Mageia: Security Advisory (MGASA-2013-0306)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(2|3)");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0306");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0306.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.ro/2013/10/stable-channel-update.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11361");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable, chromium-browser-stable, chromium-browser-stable' package(s) announced via the MGASA-2013-0306 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This updates chromium-browser to the latest stable version, fixing
multiple security vulnerabilities.

Security fixes:
CVE-2013-2906: Races in Web Audio
CVE-2013-2907: Out of bounds read in Window.prototype object
CVE-2013-2908: Address bar spoofing related to the '204 No Content'
 status code
CVE-2013-2909: Use after free in inline-block rendering
CVE-2013-2910: Use-after-free in Web Audio
CVE-2013-2911: Use-after-free in XSLT
CVE-2013-2912: Use-after-free in PPAPI
CVE-2013-2913: Use-after-free in XML document parsing
CVE-2013-2914: Use after free in the Windows color chooser dialog
CVE-2013-2915: Address bar spoofing via a malformed scheme
CVE-2013-2916: Address bar spoofing related to the '204 No Content'
 status code
CVE-2013-2917: Out of bounds read in Web Audio
CVE-2013-2918: Use-after-free in DOM
CVE-2013-2919: Memory corruption in V8
CVE-2013-2920: Out of bounds read in URL parsing
CVE-2013-2921: Use-after-free in resource loader
CVE-2013-2922: Use-after-free in template element
CVE-2013-2923: Various fixes from internal audits, fuzzing and other
 initiatives
CVE-2013-2924: Use-after-free in ICU. Upstream bug");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~30.0.1599.66~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~30.0.1599.66~1.mga2", rls:"MAGEIA2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~30.0.1599.66~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~30.0.1599.66~1.mga3.tainted", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~30.0.1599.66~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~30.0.1599.66~1.mga3.tainted", rls:"MAGEIA3"))) {
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
