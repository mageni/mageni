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
  script_oid("1.3.6.1.4.1.25623.1.0.854397");
  script_version("2022-02-04T08:16:44+0000");
  script_cve_id("CVE-2021-29981", "CVE-2021-29982", "CVE-2021-29987", "CVE-2021-29991", "CVE-2021-32810", "CVE-2021-38492", "CVE-2021-38493", "CVE-2021-38495", "CVE-2021-38496", "CVE-2021-38497", "CVE-2021-38498", "CVE-2021-38500", "CVE-2021-38501", "CVE-2021-38502", "CVE-2021-38503", "CVE-2021-38504", "CVE-2021-38505", "CVE-2021-38506", "CVE-2021-38507", "CVE-2021-38508", "CVE-2021-38509", "CVE-2021-38510", "CVE-2021-40529", "CVE-2021-43528", "CVE-2021-43536", "CVE-2021-43537", "CVE-2021-43538", "CVE-2021-43539", "CVE-2021-43541", "CVE-2021-43542", "CVE-2021-43543", "CVE-2021-43545", "CVE-2021-43546");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-02-04 11:00:11 +0000 (Fri, 04 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-01 06:35:16 +0000 (Tue, 01 Feb 2022)");
  script_name("openSUSE: Security Advisory for MozillaThunderbird (openSUSE-SU-2021:1635-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1635-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YVVRA5LXBWWHGQPQLJYZRWPCG4E2L7WQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the openSUSE-SU-2021:1635-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

  - Update to version 91.4 MFSA 2021-54 (bsc#1193485)

  - CVE-2021-43536: URL leakage when navigating while executing asynchronous
       function

  - CVE-2021-43537: Heap buffer overflow when using structured clone

  - CVE-2021-43538: Missing fullscreen and pointer lock notification when
       requesting both

  - CVE-2021-43539: GC rooting failure when calling wasm instance methods

  - CVE-2021-43541: External protocol handler parameters were unescaped

  - CVE-2021-43542: XMLHttpRequest error codes could have leaked the
       existence of an external protocol handler

  - CVE-2021-43543: Bypass of CSP sandbox directive when embedding

  - CVE-2021-43545: Denial of Service when using the Location API in a loop

  - CVE-2021-43546: Cursor spoofing could overlay user interface when native
       cursor is zoomed

  - CVE-2021-43528: JavaScript unexpectedly enabled for the composition area

  - Update to version 91.3.2

  - CVE-2021-40529: Fixed ElGamal implementation could allow plaintext
       recovery (bsc#1190244)

  - Update to version 91.3 MFSA 2021-50 (bsc#1192250)

  - CVE-2021-38503: Fixed iframe sandbox rules did not apply to XSLT
       stylesheets

  - CVE-2021-38504: Fixed use-after-free in file picker dialog

  - CVE-2021-38505: Fixed Windows 10 Cloud Clipboard may have recorded
       sensitive user data

  - CVE-2021-38506: Fixed Thunderbird could be coaxed into going into
       fullscreen mode without notification or warning

  - CVE-2021-38507: Fixed opportunistic Encryption in HTTP2 could be used to
       bypass the Same-Origin-Policy on services hosted on other ports

  - CVE-2021-38508: Fixed permission Prompt could be overlaid, resulting in
       user confusion and potential spoofing

  - CVE-2021-38509: Fixed Javascript alert box could have been spoofed onto
       an arbitrary domain

  - CVE-2021-38510: Fixed Download Protections were bypassed by .inetloc
       files on Mac OS

  - Fixed plain text reformatting regression (bsc#1182863)

  - Update to version 91.2 MFSA 2021-47 (bsc#1191332)

  - CVE-2021-29981: Live range splitting could have led to conflicting
       assignments in the JIT

  - CVE-2021-29982: Single bit data leak due to incorrect JIT optimization
       and type confusion

  - CVE-2021-29987: Users could have been tricked into accepting unwanted
       permissions on Linux

  - CVE-2021-32810: Data race in crossbeam-deque

  - CVE-2021-38493: Memory safety bugs fixed in Thunderbird 78.14 and
       Thunderbird ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~91.4.0~lp152.2.52.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~91.4.0~lp152.2.52.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~91.4.0~lp152.2.52.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~91.4.0~lp152.2.52.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~91.4.0~lp152.2.52.1", rls:"openSUSELeap15.2"))) {
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