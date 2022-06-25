# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853296");
  script_version("2020-07-24T07:28:01+0000");
  script_cve_id("CVE-2020-12402", "CVE-2020-12415", "CVE-2020-12416", "CVE-2020-12417", "CVE-2020-12418", "CVE-2020-12419", "CVE-2020-12420", "CVE-2020-12421", "CVE-2020-12422", "CVE-2020-12423", "CVE-2020-12424", "CVE-2020-12425", "CVE-2020-12426");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-07-24 10:05:16 +0000 (Fri, 24 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-21 03:02:22 +0000 (Tue, 21 Jul 2020)");
  script_name("openSUSE: Security Advisory for MozillaFirefox (openSUSE-SU-2020:1017-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:1017-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00049.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the openSUSE-SU-2020:1017-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox to version 78.0.1 ESR fixes the following
  issues:

  Security issues fixed:

  - CVE-2020-12415: AppCache manifest poisoning due to url encoded character
  processing (bsc#1173576).

  - CVE-2020-12416: Use-after-free in WebRTC VideoBroadcaster (bsc#1173576).

  - CVE-2020-12417: Memory corruption due to missing sign-extension for
  ValueTags on ARM64 (bsc#1173576).

  - CVE-2020-12418: Information disclosure due to manipulated URL object
  (bsc#1173576).

  - CVE-2020-12419: Use-after-free in nsGlobalWindowInner (bsc#1173576).

  - CVE-2020-12420: Use-After-Free when trying to connect to a STUN server
  (bsc#1173576).

  - CVE-2020-12402: RSA Key Generation vulnerable to side-channel attack
  (bsc#1173576).

  - CVE-2020-12421: Add-On updates did not respect the same certificate
  trust rules as software updates (bsc#1173576).

  - CVE-2020-12422: Integer overflow in nsJPEGEncoder::emptyOutputBuffer
  (bsc#1173576).

  - CVE-2020-12423: DLL Hijacking due to searching %PATH% for a library
  (bsc#1173576).

  - CVE-2020-12424: WebRTC permission prompt could have been bypassed by a
  compromised content process (bsc#1173576).

  - CVE-2020-12425: Out of bound read in Date.parse() (bsc#1173576).

  - CVE-2020-12426: Memory safety bugs fixed in Firefox 78 (bsc#1173576).

  - FIPS: MozillaFirefox: allow /proc/sys/crypto/fips_enabled (bsc#1167231).

  Non-security issues fixed:

  - Fixed interaction with freetype6 (bsc#1173613).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1017=1");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~78.0.1~lp151.2.53.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~78.0.1~lp151.2.53.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~78.0.1~lp151.2.53.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~78.0.1~lp151.2.53.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~78.0.1~lp151.2.53.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~78.0.1~lp151.2.53.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~78.0.1~lp151.2.53.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~78.0.1~lp151.2.53.1", rls:"openSUSELeap15.1"))) {
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