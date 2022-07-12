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
  script_oid("1.3.6.1.4.1.25623.1.0.852759");
  script_version("2019-11-04T08:05:52+0000");
  script_cve_id("CVE-2019-13699", "CVE-2019-13700", "CVE-2019-13701", "CVE-2019-13702", "CVE-2019-13703", "CVE-2019-13704", "CVE-2019-13705", "CVE-2019-13706", "CVE-2019-13707", "CVE-2019-13708", "CVE-2019-13709", "CVE-2019-13710", "CVE-2019-13711", "CVE-2019-13713", "CVE-2019-13714", "CVE-2019-13715", "CVE-2019-13716", "CVE-2019-13717", "CVE-2019-13718", "CVE-2019-13719", "CVE-2019-15903");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-11-04 08:05:52 +0000 (Mon, 04 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-02 03:00:57 +0000 (Sat, 02 Nov 2019)");
  script_name("openSUSE Update for chromium, openSUSE-SU-2019:2420-1 (chromium, )");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00000.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium, '
  package(s) announced via the openSUSE-SU-2019:2420_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium, re2 fixes the following issues:

  Chromium was updated to 78.0.3904.70 boo#1154806:

  * CVE-2019-13699: Use-after-free in media

  * CVE-2019-13700: Buffer overrun in Blink

  * CVE-2019-13701: URL spoof in navigation

  * CVE-2019-13702: Privilege elevation in Installer

  * CVE-2019-13703: URL bar spoofing

  * CVE-2019-13704: CSP bypass

  * CVE-2019-13705: Extension permission bypass

  * CVE-2019-13706: Out-of-bounds read in PDFium

  * CVE-2019-13707: File storage disclosure

  * CVE-2019-13708: HTTP authentication spoof

  * CVE-2019-13709: File download protection bypass

  * CVE-2019-13710: File download protection bypass

  * CVE-2019-13711: Cross-context information leak

  * CVE-2019-15903: Buffer overflow in expat

  * CVE-2019-13713: Cross-origin data leak

  * CVE-2019-13714: CSS injection

  * CVE-2019-13715: Address bar spoofing

  * CVE-2019-13716: Service worker state error

  * CVE-2019-13717: Notification obscured

  * CVE-2019-13718: IDN spoof

  * CVE-2019-13719: Notification obscured

  * Various fixes from internal audits, fuzzing and other initiatives

  - Use internal resources for icon and appdata


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2420=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2420=1");

  script_tag(name:"affected", value:"'chromium, ' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"libre2", rpm:"libre2~0~20190901~lp150.25.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libre2", rpm:"libre2~0~debuginfo~20190901~lp150.25.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"re2-debugsource", rpm:"re2-debugsource~20190901~lp150.25.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"re2-devel", rpm:"re2-devel~20190901~lp150.25.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~78.0.3904.70~lp150.248.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~78.0.3904.70~lp150.248.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~78.0.3904.70~lp150.248.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~78.0.3904.70~lp150.248.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~78.0.3904.70~lp150.248.2", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libre2", rpm:"libre2~0~32bit~20190901~lp150.25.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libre2", rpm:"libre2~0~32bit~debuginfo~20190901~lp150.25.1", rls:"openSUSELeap15.0"))) {
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