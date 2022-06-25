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
  script_oid("1.3.6.1.4.1.25623.1.0.853553");
  script_version("2020-11-06T08:04:05+0000");
  script_cve_id("CVE-2020-14004");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-11-06 11:47:26 +0000 (Fri, 06 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-04 04:01:11 +0000 (Wed, 04 Nov 2020)");
  script_name("openSUSE: Security Advisory for icinga2 (openSUSE-SU-2020:1820-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.2|openSUSELeap15\.1)");

  script_xref(name:"openSUSE-SU", value:"2020:1820-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-11/msg00014.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icinga2'
  package(s) announced via the openSUSE-SU-2020:1820-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for icinga2 fixes the following issues:

  - Info that since version 2.12.0 following security issue is fixed:
  prepare-dirs script allows for symlink attack in the icinga user
  context. boo#1172171 (CVE-2020-14004)

  Update to 2.12.1:

  * Bugfixes
  + Core

  - Fix crashes during config update #8348 #8345

  - Fix crash while removing a downtime #8228

  - Ensure the daemon doesn't get killed by logrotate #8170

  - Fix hangup during shutdown #8211

  - Fix a deadlock in Icinga DB #8168

  - Clean up zombie processes during reload #8376

  - Reduce check latency #8276
  + IDO

  - Prevent unnecessary IDO updates #8327 #8320

  - Commit IDO MySQL transactions earlier #8349

  - Make sure to insert IDO program status #8330

  - Improve IDO queue stats logging #8271 #8328 #8379
  + Misc

  - Ensure API connections are closed properly #8293

  - Prevent unnecessary notifications #8299

  - Don't skip null values of command arguments #8174

  - Fix Windows .exe version #8234

  - Reset Icinga check warning after successful config update #8189

  Update to 2.12.0:

  * Breaking changes

  - Deprecate Windows plugins in favor of our

  - PowerShell plugins #8071

  - Deprecate Livestatus #8051

  - Refuse acknowledging an already acknowledged checkable #7695

  - Config lexer: complain on EOF in heredocs, i.e. {{{abc<EOF> #7541

  * Enhancements
  + Core

  - Implement new database backend: Icinga DB #7571

  - Re-send notifications previously suppressed by their time periods
  #7816
  + API

  - Host/Service: Add acknowledgement_last_change and next_update
  attributes #7881 #7534

  - Improve error message for POST queries #7681

  - /v1/actions/remove-comment: let users specify themselves #7646

  - /v1/actions/remove-downtime: let users specify themselves #7645

  - /v1/config/stages: Add 'activate' parameter #7535
  + CLI

  - Add pki verify command for better TLS certificate troubleshooting
  #7843

  - Add OpenSSL version to 'Build' section in --version #7833

  - Improve experience with 'Node Setup for Agents/Satellite' #7835
  + DSL

  - Add get_template() and get_templates() #7632

  - MacroProcessor::ResolveArguments(): skip null argument values #7567

  - Fix crash due to dependency apply rule with ignore_on_error and
  non-existing parent #7538

  - Introduce ternary operator (x ? y : z) #7442

  - LegacyTimePeriod: support specifying seconds #7439

  - Add support for Lambda Closures (() use(x) => x and () use(x) => {
  return x }) #7417
  + ITL

  - Add notemp parameter to oracle health #7748

  - Add extended checks options to snmp-interface command template
  #7602

  - Add file a ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'icinga2' package(s) on openSUSE Leap 15.2, openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"icinga2", rpm:"icinga2~2.12.1~lp152.3.3.3", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-bin", rpm:"icinga2-bin~2.12.1~lp152.3.3.3", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-bin-debuginfo", rpm:"icinga2-bin-debuginfo~2.12.1~lp152.3.3.3", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-common", rpm:"icinga2-common~2.12.1~lp152.3.3.3", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-debuginfo", rpm:"icinga2-debuginfo~2.12.1~lp152.3.3.3", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-debugsource", rpm:"icinga2-debugsource~2.12.1~lp152.3.3.3", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-doc", rpm:"icinga2-doc~2.12.1~lp152.3.3.3", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-ido-mysql", rpm:"icinga2-ido-mysql~2.12.1~lp152.3.3.3", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-ido-mysql-debuginfo", rpm:"icinga2-ido-mysql-debuginfo~2.12.1~lp152.3.3.3", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-ido-pgsql", rpm:"icinga2-ido-pgsql~2.12.1~lp152.3.3.3", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-ido-pgsql-debuginfo", rpm:"icinga2-ido-pgsql-debuginfo~2.12.1~lp152.3.3.3", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nano-icinga2", rpm:"nano-icinga2~2.12.1~lp152.3.3.3", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-icinga2", rpm:"vim-icinga2~2.12.1~lp152.3.3.3", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"icinga2", rpm:"icinga2~2.12.1~lp151.2.3.4", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-bin", rpm:"icinga2-bin~2.12.1~lp151.2.3.4", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-bin-debuginfo", rpm:"icinga2-bin-debuginfo~2.12.1~lp151.2.3.4", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-common", rpm:"icinga2-common~2.12.1~lp151.2.3.4", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-debuginfo", rpm:"icinga2-debuginfo~2.12.1~lp151.2.3.4", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-debugsource", rpm:"icinga2-debugsource~2.12.1~lp151.2.3.4", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-doc", rpm:"icinga2-doc~2.12.1~lp151.2.3.4", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-ido-mysql", rpm:"icinga2-ido-mysql~2.12.1~lp151.2.3.4", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-ido-mysql-debuginfo", rpm:"icinga2-ido-mysql-debuginfo~2.12.1~lp151.2.3.4", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-ido-pgsql", rpm:"icinga2-ido-pgsql~2.12.1~lp151.2.3.4", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icinga2-ido-pgsql-debuginfo", rpm:"icinga2-ido-pgsql-debuginfo~2.12.1~lp151.2.3.4", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nano-icinga2", rpm:"nano-icinga2~2.12.1~lp151.2.3.4", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-icinga2", rpm:"vim-icinga2~2.12.1~lp151.2.3.4", rls:"openSUSELeap15.1"))) {
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