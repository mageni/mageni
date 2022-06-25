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
  script_oid("1.3.6.1.4.1.25623.1.0.852636");
  script_version("2019-07-25T11:54:35+0000");
  script_cve_id("CVE-2018-11499", "CVE-2018-19797", "CVE-2018-19827", "CVE-2018-19837", "CVE-2018-19838", "CVE-2018-19839", "CVE-2018-20190", "CVE-2018-20821", "CVE-2018-20822", "CVE-2019-6283", "CVE-2019-6284", "CVE-2019-6286");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-07-25 11:54:35 +0000 (Thu, 25 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-24 02:01:46 +0000 (Wed, 24 Jul 2019)");
  script_name("openSUSE Update for libsass openSUSE-SU-2019:1791-1 (libsass)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-07/msg00047.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsass'
  package(s) announced via the openSUSE-SU-2019:1791_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libsass to version 3.6.1 fixes the following issues:

  Security issues fixed:

  - CVE-2019-6283: Fixed heap-buffer-overflow in
  Sass::Prelexer::parenthese_scope(char const*) (boo#1121943).

  - CVE-2019-6284: Fixed heap-based buffer over-read exists in
  Sass:Prelexer:alternatives (boo#1121944).

  - CVE-2019-6286: Fixed heap-based buffer over-read exists in
  Sass:Prelexer:skip_over_scopes (boo#1121945).

  - CVE-2018-11499: Fixed use-after-free vulnerability in
  sass_context.cpp:handle_error (boo#1096894).

  - CVE-2018-19797: Disallowed parent selector in selector_fns arguments
  (boo#1118301).

  - CVE-2018-19827: Fixed use-after-free vulnerability exists in the
  SharedPtr class (boo#1118346).

  - CVE-2018-19837: Fixed stack overflow in Eval::operator() (boo#1118348).

  - CVE-2018-19838: Fixed stack-overflow at IMPLEMENT_AST_OPERATORS
  expansion (boo#1118349).

  - CVE-2018-19839: Fixed buffer-overflow (OOB read) against some invalid
  input (boo#1118351).

  - CVE-2018-20190: Fixed Null pointer dereference in
  Sass::Eval::operator()(Sass::Supports_Operator*) (boo#1119789).

  - CVE-2018-20821: Fixed uncontrolled recursion in
  Sass:Parser:parse_css_variable_value (boo#1133200).

  - CVE-2018-20822: Fixed stack-overflow at Sass::Inspect::operator()
  (boo#1133201).


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1791=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1791=1");

  script_tag(name:"affected", value:"'libsass' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"libsass-3_6_1-1", rpm:"libsass-3_6_1-1~3.6.1~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsass-3_6_1-1-debuginfo", rpm:"libsass-3_6_1-1-debuginfo~3.6.1~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsass-debugsource", rpm:"libsass-debugsource~3.6.1~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsass-devel", rpm:"libsass-devel~3.6.1~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
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