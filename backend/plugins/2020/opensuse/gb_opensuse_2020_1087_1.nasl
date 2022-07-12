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
  script_oid("1.3.6.1.4.1.25623.1.0.853318");
  script_version("2020-08-07T07:29:19+0000");
  script_cve_id("CVE-2020-14039", "CVE-2020-15586");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-08-07 10:04:11 +0000 (Fri, 07 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-07-27 03:01:24 +0000 (Mon, 27 Jul 2020)");
  script_name("openSUSE: Security Advisory for go1.13 (openSUSE-SU-2020:1087-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:1087-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00077.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.13'
  package(s) announced via the openSUSE-SU-2020:1087-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.13 fixes the following issues:

  - go1.13.14 (released 2020/07/16) includes fixes to the compiler, vet, and
  the database/sql, net/http, and reflect packages Refs bsc#1149259 go1.13
  release tracking

  * go#39925 net/http: panic on malformed  If-None-Match Header with
  http.ServeContent

  * go#39848 cmd/compile: internal compile error when using sync.Pool:
  mismatched zero/store sizes

  * go#39823 cmd/go: TestBuildIDContainsArchModeEnv/386 fails on linux/386
  in Go 1.14 and 1.13, not 1.15

  * go#39697 reflect: panic from malloc after MakeFunc function returns
  value that is also stored globally

  * go#39561 cmd/compile/internal/ssa: TestNexting/dlv-dbg-hist failing on
  linux-386-longtest builder because it tries to use an older version of
  dlv which only supports linux/amd64

  * go#39538 net: TestDialParallel is flaky on windows-amd64-longtest

  * go#39287 cmd/vet: update for new number formats

  * go#40211 net/http: Expect 100-continue panics in httputil.ReverseProxy
  bsc#1174153 CVE-2020-15586

  * go#40209 crypto/x509: Certificate.Verify method seemingly ignoring EKU
  requirements on Windows bsc#1174191 CVE-2020-14039 (Windows only)

  * go#38932 runtime: preemption in startTemplateThread may cause infinite
  hang

  * go#36689 go/types, math/big: data race in go/types due to math/big.Rat
  accessors unsafe for concurrent use

  - Add patch to ensure /etc/hosts is used if /etc/nsswitch.conf is not
  present bsc#1172868 gh#golang/go#35305

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1087=1");

  script_tag(name:"affected", value:"'go1.13' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"go1.13", rpm:"go1.13~1.13.14~lp151.5.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.13-doc", rpm:"go1.13-doc~1.13.14~lp151.5.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.13-race", rpm:"go1.13-race~1.13.14~lp151.5.1", rls:"openSUSELeap15.1"))) {
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
