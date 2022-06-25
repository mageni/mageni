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
  script_oid("1.3.6.1.4.1.25623.1.0.852623");
  script_version("2019-07-25T11:54:35+0000");
  script_cve_id("CVE-2017-17742", "CVE-2018-1000073", "CVE-2018-1000074", "CVE-2018-1000075",
                "CVE-2018-1000076", "CVE-2018-1000077", "CVE-2018-1000078", "CVE-2018-1000079",
                "CVE-2018-16395", "CVE-2018-16396", "CVE-2018-6914", "CVE-2018-8777",
                "CVE-2018-8778", "CVE-2018-8779", "CVE-2018-8780", "CVE-2019-8320",
                "CVE-2019-8321", "CVE-2019-8322", "CVE-2019-8323", "CVE-2019-8324",
                "CVE-2019-8325");
  script_tag(name:"cvss_base", value:"8.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-25 11:54:35 +0000 (Thu, 25 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-22 02:00:43 +0000 (Mon, 22 Jul 2019)");
  script_name("openSUSE Update for ruby-bundled-gems-rpmhelper, openSUSE-SU-2019:1771-1 (ruby-bundled-gems-rpmhelper, )");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-07/msg00036.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby-bundled-gems-rpmhelper, '
  package(s) announced via the openSUSE-SU-2019:1771_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ruby2.5 and ruby-bundled-gems-rpmhelper fixes the
  following issues:

  Security issues fixed:

  - CVE-2019-8320: Delete directory using symlink when decompressing tar
  (bsc#1130627)

  - CVE-2019-8321: Escape sequence injection vulnerability in verbose
  (bsc#1130623)

  - CVE-2019-8322: Escape sequence injection vulnerability in gem
  owner  (bsc#1130622)

  - CVE-2019-8323: Escape sequence injection vulnerability in API response
  handling  (bsc#1130620)

  - CVE-2019-8324: Installing a malicious gem may lead to arbitrary code
  execution  (bsc#1130617)

  - CVE-2019-8325: Escape sequence injection vulnerability in errors
  (bsc#1130611)


  Ruby 2.5 was updated to 2.5.3:

  This release includes some bug fixes and some security fixes.

  Security issues fixed:

  - CVE-2018-16396: Tainted flags are not propagated in Array#pack and
  String#unpack with some directives (bsc#1112532)

  - CVE-2018-16395: OpenSSL::X509::Name equality check does not work
  correctly (bsc#1112530)

  Ruby 2.5 was updated to 2.5.1:

  This release includes some bug fixes and some security fixes.

  Security issues fixed:

  - CVE-2017-17742: HTTP response splitting in WEBrick (bsc#1087434)

  - CVE-2018-6914: Unintentional file and directory creation with directory
  traversal in tempfile and tmpdir (bsc#1087441)

  - CVE-2018-8777: DoS by large request in WEBrick (bsc#1087436)

  - CVE-2018-8778: Buffer under-read in String#unpack (bsc#1087433)

  - CVE-2018-8779: Unintentional socket creation by poisoned NUL byte in
  UNIXServer and UNIXSocket (bsc#1087440)

  - CVE-2018-8780: Unintentional directory traversal by poisoned NUL byte in
  Dir (bsc#1087437)

  - Multiple vulnerabilities in RubyGems were fixed:

  - CVE-2018-1000079: Fixed path traversal issue during gem installation
  allows to write to arbitrary filesystem locations (bsc#1082058)

  - CVE-2018-1000075: Fixed infinite loop vulnerability due to negative
  size in tar header causes Denial of Service (bsc#1082014)

  - CVE-2018-1000078: Fixed XSS vulnerability in homepage attribute when
  displayed via gem server (bsc#1082011)

  - CVE-2018-1000077: Fixed that missing URL validation on spec home
  attribute allows malicious gem to set an invalid homepa ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'ruby-bundled-gems-rpmhelper, ' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"ruby-bundled-gems-rpmhelper", rpm:"ruby-bundled-gems-rpmhelper~0.0.2~lp150.2.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-doc-ri", rpm:"ruby2.5-doc-ri~2.5.5~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libruby2_5-2_5", rpm:"libruby2_5-2_5~2.5.5~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libruby2_5-2_5-debuginfo", rpm:"libruby2_5-2_5-debuginfo~2.5.5~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5", rpm:"ruby2.5~2.5.5~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-debuginfo", rpm:"ruby2.5-debuginfo~2.5.5~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-debugsource", rpm:"ruby2.5-debugsource~2.5.5~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-devel", rpm:"ruby2.5-devel~2.5.5~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-devel-extra", rpm:"ruby2.5-devel-extra~2.5.5~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-doc", rpm:"ruby2.5-doc~2.5.5~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-stdlib", rpm:"ruby2.5-stdlib~2.5.5~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uby2.5-stdlib-debuginfo", rpm:"uby2.5-stdlib-debuginfo~2.5.5~lp150.3.3.1", rls:"openSUSELeap15.0"))) {
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
