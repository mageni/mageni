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
  script_oid("1.3.6.1.4.1.25623.1.0.852791");
  script_version("2019-12-03T07:07:39+0000");
  script_cve_id("CVE-2019-8551", "CVE-2019-8558", "CVE-2019-8559", "CVE-2019-8563", "CVE-2019-8625", "CVE-2019-8674", "CVE-2019-8681", "CVE-2019-8684", "CVE-2019-8686", "CVE-2019-8687", "CVE-2019-8688", "CVE-2019-8689", "CVE-2019-8690", "CVE-2019-8707", "CVE-2019-8710", "CVE-2019-8719", "CVE-2019-8720", "CVE-2019-8726", "CVE-2019-8733", "CVE-2019-8735", "CVE-2019-8743", "CVE-2019-8763", "CVE-2019-8764", "CVE-2019-8765", "CVE-2019-8766", "CVE-2019-8768", "CVE-2019-8769", "CVE-2019-8771", "CVE-2019-8782", "CVE-2019-8783", "CVE-2019-8808", "CVE-2019-8811", "CVE-2019-8812", "CVE-2019-8813", "CVE-2019-8814", "CVE-2019-8815", "CVE-2019-8816", "CVE-2019-8819", "CVE-2019-8820", "CVE-2019-8821", "CVE-2019-8822", "CVE-2019-8823");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-12-03 07:07:39 +0000 (Tue, 03 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-01 03:00:47 +0000 (Sun, 01 Dec 2019)");
  script_name("openSUSE Update for webkit2gtk3 openSUSE-SU-2019:2587-1 (webkit2gtk3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-11/msg00073.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the openSUSE-SU-2019:2587_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 to version 2.26.2 fixes the following issues:

  Webkit2gtk3 was updated to version 2.26.2 (WSA-2019-0005 and
  WSA-2019-0006, bsc#1155321 bsc#1156318)

  Security issues addressed:

  - CVE-2019-8625: Fixed a logic issue where by processing maliciously
  crafted web content may lead to universal cross site scripting.

  - CVE-2019-8674: Fixed a logic issue where by processing maliciously
  crafted web content may lead to universal cross site scripting.

  - CVE-2019-8707: Fixed multiple  memory corruption issues where by
  processing maliciously crafted web content may lead to arbitrary code
  execution.

  - CVE-2019-8719: Fixed a logic issue where by processing maliciously
  crafted web content may lead to universal cross site scripting.

  - CVE-2019-8720: Fixed multiple memory corruption issues where by
  processing maliciously crafted web content may lead to arbitrary code
  execution.

  - CVE-2019-8726: Fixed multiple memory corruption issues where by
  processing maliciously crafted web content may lead to arbitrary code
  execution.

  - CVE-2019-8733: Fixed multiple memory corruption issues where by
  processing maliciously crafted web content may lead to arbitrary code
  execution.

  - CVE-2019-8735: Fixed multiple memory corruption issues where by
  processing maliciously crafted web content may lead to arbitrary code
  execution.

  - CVE-2019-8763: Fixed multiple  memory corruption issues where by
  processing maliciously crafted web content may lead to arbitrary code
  execution.

  - CVE-2019-8768: Fixed an issue where a user may be unable to delete
  browsing history items.

  - CVE-2019-8769: Fixed an issue where a maliciously crafted website may
  reveal browsing history.

  - CVE-2019-8771: Fixed an issue where a maliciously crafted web content
  may violate iframe sandboxing policy.

  - CVE-2019-8710: Fixed multiple memory corruption issues where by
  processing maliciously crafted web content may lead to arbitrary code
  execution.

  - CVE-2019-8743: Fixed multiple memory corruption issues where by
  processing maliciously crafted web content may lead to arbitrary code
  execution.

  - CVE-2019-8764: Fixed a logic issue where by processing maliciously
  crafted web content may lead to universal cross site scripting.

  - CVE-2019-8765: Fixed multiple memory corruption issues where by
  processing maliciously crafted web content may lead to arbitrary code
  execution.

  - CVE-2019-8766: Fixed multiple memory corruption issues where by
  processing maliciously crafted web content may lead to arbitrary code
  execution.

  - CVE-2019-8782: Fixed m ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18", rpm:"libjavascriptcoregtk-4_0-18~2.26.2~lp150.2.28.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18-debuginfo", rpm:"libjavascriptcoregtk-4_0-18-debuginfo~2.26.2~lp150.2.28.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37", rpm:"libwebkit2gtk-4_0-37~2.26.2~lp150.2.28.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37-debuginfo", rpm:"libwebkit2gtk-4_0-37-debuginfo~2.26.2~lp150.2.28.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_0", rpm:"typelib-1_0-JavaScriptCore-4_0~2.26.2~lp150.2.28.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_0", rpm:"typelib-1_0-WebKit2-4_0~2.26.2~lp150.2.28.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2WebExtension-4_0", rpm:"typelib-1_0-WebKit2WebExtension-4_0~2.26.2~lp150.2.28.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4", rpm:"webkit-jsc-4~2.26.2~lp150.2.28.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4-debuginfo", rpm:"webkit-jsc-4-debuginfo~2.26.2~lp150.2.28.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles", rpm:"webkit2gtk-4_0-injected-bundles~2.26.2~lp150.2.28.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles-debuginfo", rpm:"webkit2gtk-4_0-injected-bundles-debuginfo~2.26.2~lp150.2.28.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-debugsource", rpm:"webkit2gtk3-debugsource~2.26.2~lp150.2.28.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-devel", rpm:"webkit2gtk3-devel~2.26.2~lp150.2.28.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-minibrowser", rpm:"webkit2gtk3-minibrowser~2.26.2~lp150.2.28.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-minibrowser-debuginfo", rpm:"webkit2gtk3-minibrowser-debuginfo~2.26.2~lp150.2.28.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk3-lang", rpm:"libwebkit2gtk3-lang~2.26.2~lp150.2.28.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18-32bit", rpm:"libjavascriptcoregtk-4_0-18-32bit~2.26.2~lp150.2.28.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18-32bit-debuginfo", rpm:"libjavascriptcoregtk-4_0-18-32bit-debuginfo~2.26.2~lp150.2.28.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37-32bit", rpm:"libwebkit2gtk-4_0-37-32bit~2.26.2~lp150.2.28.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37-32bit-debuginfo", rpm:"libwebkit2gtk-4_0-37-32bit-debuginfo~2.26.2~lp150.2.28.1", rls:"openSUSELeap15.0"))) {
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
