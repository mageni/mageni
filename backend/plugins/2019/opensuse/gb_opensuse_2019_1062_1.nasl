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
  script_oid("1.3.6.1.4.1.25623.1.0.852369");
  script_version("2019-04-26T08:24:31+0000");
  script_cve_id("CVE-2019-5787", "CVE-2019-5788", "CVE-2019-5789", "CVE-2019-5790",
                "CVE-2019-5791", "CVE-2019-5792", "CVE-2019-5793", "CVE-2019-5794",
                "CVE-2019-5795", "CVE-2019-5796", "CVE-2019-5797", "CVE-2019-5798",
                "CVE-2019-5799", "CVE-2019-5800", "CVE-2019-5801", "CVE-2019-5802",
                "CVE-2019-5803", "CVE-2019-5804");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-04-26 08:24:31 +0000 (Fri, 26 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-03 06:41:42 +0000 (Wed, 03 Apr 2019)");
  script_name("openSUSE Update for chromium openSUSE-SU-2019:1062-1 (chromium)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-03/msg00038.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2019:1062_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium to version 73.0.3683.75 fixes the following
  issues:

  Security issues fixed (bsc#1129059):

  - CVE-2019-5787: Fixed a use after free in Canvas.

  - CVE-2019-5788: Fixed a use after free in FileAPI.

  - CVE-2019-5789: Fixed a use after free in WebMIDI.

  - CVE-2019-5790: Fixed a heap buffer overflow in V8.

  - CVE-2019-5791: Fixed a type confusion in V8.

  - CVE-2019-5792: Fixed an integer overflow in PDFium.

  - CVE-2019-5793: Fixed excessive permissions for private API in Extensions.

  - CVE-2019-5794: Fixed security UI spoofing.

  - CVE-2019-5795: Fixed an integer overflow in PDFium.

  - CVE-2019-5796: Fixed a race condition in Extensions.

  - CVE-2019-5797: Fixed a race condition in DOMStorage.

  - CVE-2019-5798: Fixed an out of bounds read in Skia.

  - CVE-2019-5799: Fixed a CSP bypass with blob URL.

  - CVE-2019-5800: Fixed a CSP bypass with blob URL.

  - CVE-2019-5801: Fixed an incorrect Omnibox display on iOS.

  - CVE-2019-5802: Fixed security UI spoofing.

  - CVE-2019-5803: Fixed a CSP bypass with Javascript URLs'.

  - CVE-2019-5804: Fixed a command line injection on Windows.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1062=1");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~73.0.3683.75~lp150.206.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~73.0.3683.75~lp150.206.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~73.0.3683.75~lp150.206.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~73.0.3683.75~lp150.206.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~73.0.3683.75~lp150.206.1", rls:"openSUSELeap15.0"))) {
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
