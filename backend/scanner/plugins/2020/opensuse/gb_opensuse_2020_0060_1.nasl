# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853011");
  script_version("2020-01-28T10:45:23+0000");
  script_cve_id("CVE-2019-17015", "CVE-2019-17016", "CVE-2019-17017", "CVE-2019-17021", "CVE-2019-17022", "CVE-2019-17024", "CVE-2019-17026");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-28 10:45:23 +0000 (Tue, 28 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-27 09:18:52 +0000 (Mon, 27 Jan 2020)");
  script_name("openSUSE: Security Advisory for MozillaFirefox (openSUSE-SU-2020:0060_1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-01/msg00029.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the openSUSE-SU-2020:0060_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

  - Firefox Extended Support Release 68.4.1 ESR

  * Fixed: Security fix MFSA 2020-03 (bsc#1160498)

  * CVE-2019-17026 (bmo#1607443) IonMonkey type confusion with
  StoreElementHole and FallibleStoreElement

  - Firefox Extended Support Release 68.4.0 ESR

  * Fixed: Various security fixes MFSA 2020-02 (bsc#1160305)

  * CVE-2019-17015 (bmo#1599005) Memory corruption in parent process
  during new content process initialization on Windows

  * CVE-2019-17016 (bmo#1599181) Bypass of @namespace CSS sanitization
  during pasting

  * CVE-2019-17017 (bmo#1603055) Type Confusion in XPCVariant.cpp

  * CVE-2019-17021 (bmo#1599008) Heap address disclosure in parent process
  during content process initialization on Windows

  * CVE-2019-17022 (bmo#1602843) CSS sanitization does not escape HTML tags

  * CVE-2019-17024 (bmo#1507180, bmo#1595470, bmo#1598605, bmo#1601826)
  Memory safety bugs fixed in Firefox 72 and Firefox ESR 68.4

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-60=1");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~68.4.1~lp151.2.24.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~68.4.1~lp151.2.24.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~68.4.1~lp151.2.24.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~68.4.1~lp151.2.24.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~68.4.1~lp151.2.24.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~68.4.1~lp151.2.24.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~68.4.1~lp151.2.24.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~68.4.1~lp151.2.24.1", rls:"openSUSELeap15.1"))) {
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