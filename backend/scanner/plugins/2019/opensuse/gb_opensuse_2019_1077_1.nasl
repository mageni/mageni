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
  script_oid("1.3.6.1.4.1.25623.1.0.852357");
  script_version("2019-05-03T10:20:18+0000");
  script_cve_id("CVE-2018-18506", "CVE-2019-9788", "CVE-2019-9790", "CVE-2019-9791",
                "CVE-2019-9792", "CVE-2019-9793", "CVE-2019-9794", "CVE-2019-9795",
                "CVE-2019-9796", "CVE-2019-9810", "CVE-2019-9813");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 10:20:18 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2019-04-03 06:41:10 +0000 (Wed, 03 Apr 2019)");
  script_name("openSUSE Update for MozillaFirefox openSUSE-SU-2019:1077-1 (MozillaFirefox)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-03/msg00043.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the openSUSE-SU-2019:1077_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

  Mozilla Firefox was updated to 60.6.1esr / MFSA 2019-10 (bsc#1130262)

  * CVE-2019-9810: IonMonkey MArraySlice has incorrect alias information

  * CVE-2019-9813: Ionmonkey type confusion with __proto__ mutations

  Mozilla Firefox was updated to 60.6.0esr / MFSA 2019-08 (boo#1129821)

  * CVE-2019-9790: Use-after-free when removing in-use DOM elements

  * CVE-2019-9791: Type inference is incorrect for constructors entered
  through on-stack replacement with IonMonkey

  * CVE-2019-9792: IonMonkey leaks JS_OPTIMIZED_OUT magic value to script

  * CVE-2019-9793: Improper bounds checks when Spectre mitigations are
  disabled

  * CVE-2019-9794: Command line arguments not discarded during execution

  * CVE-2019-9795: Type-confusion in IonMonkey JIT compiler

  * CVE-2019-9796: Use-after-free with SMIL animation controller

  * CVE-2018-18506: Proxy Auto-Configuration file can define localhost
  access to be proxied

  * CVE-2019-9788: Memory safety bugs fixed in Firefox 66 and Firefox ESR
  60.6

  Mozilla Firefox 60.5.2esr also had one change:

  * Fix a frequent crash when reading various Reuters news articles.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1077=1");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~60.6.1~lp150.3.45.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~60.6.1~lp150.3.45.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~60.6.1~lp150.3.45.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~60.6.1~lp150.3.45.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~60.6.1~lp150.3.45.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~60.6.1~lp150.3.45.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~60.6.1~lp150.3.45.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~60.6.1~lp150.3.45.1", rls:"openSUSELeap15.0"))) {
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
