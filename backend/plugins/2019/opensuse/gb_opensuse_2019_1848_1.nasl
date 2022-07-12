# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852647");
  script_version("2019-08-14T07:16:43+0000");
  script_cve_id("CVE-2019-5850", "CVE-2019-5851", "CVE-2019-5852", "CVE-2019-5853", "CVE-2019-5854", "CVE-2019-5855", "CVE-2019-5856", "CVE-2019-5857", "CVE-2019-5858", "CVE-2019-5859", "CVE-2019-5860", "CVE-2019-5861", "CVE-2019-5862", "CVE-2019-5863", "CVE-2019-5864", "CVE-2019-5865");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-08-14 07:16:43 +0000 (Wed, 14 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-13 02:00:53 +0000 (Tue, 13 Aug 2019)");
  script_name("openSUSE Update for chromium openSUSE-SU-2019:1848-1 (chromium)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-08/msg00009.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2019:1848_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium to version 76.0.3809.87 fixes the following
  issues:

  - CVE-2019-5850: Use-after-free in offline page fetcher (boo#1143492)

  - CVE-2019-5860: Use-after-free in PDFium (boo#1143492)

  - CVE-2019-5853: Memory corruption in regexp length check (boo#1143492)

  - CVE-2019-5851: Use-after-poison in offline audio context (boo#1143492)

  - CVE-2019-5859: res: URIs can load alternative browsers (boo#1143492)

  - CVE-2019-5856: Insufficient checks on filesystem: URI permissions
  (boo#1143492)

  - CVE-2019-5855: Integer overflow in PDFium (boo#1143492)

  - CVE-2019-5865: Site isolation bypass from compromised renderer
  (boo#1143492)

  - CVE-2019-5858: Insufficient filtering of Open URL service parameters
  (boo#1143492)

  - CVE-2019-5864: Insufficient port filtering in CORS for extensions
  (boo#1143492)

  - CVE-2019-5862: AppCache not robust to compromised renderers (boo#1143492)

  - CVE-2019-5861: Click location incorrectly checked (boo#1143492)

  - CVE-2019-5857: Comparison of -0 and null yields crash (boo#1143492)

  - CVE-2019-5854: Integer overflow in PDFium text rendering (boo#1143492)

  - CVE-2019-5852: Object leak of utility functions (boo#1143492)


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1848=1");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~76.0.3809.87~lp150.224.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~76.0.3809.87~lp150.224.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~76.0.3809.87~lp150.224.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~76.0.3809.87~lp150.224.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~76.0.3809.87~lp150.224.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
