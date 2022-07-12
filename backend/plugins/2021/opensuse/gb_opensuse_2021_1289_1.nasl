# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.854176");
  script_version("2021-09-22T08:01:20+0000");
  script_cve_id("CVE-2021-29472");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-09-22 10:15:34 +0000 (Wed, 22 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-26 03:15:00 +0000 (Wed, 26 May 2021)");
  script_tag(name:"creation_date", value:"2021-09-22 01:01:45 +0000 (Wed, 22 Sep 2021)");
  script_name("openSUSE: Security Advisory for php-composer (openSUSE-SU-2021:1289-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1289-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6ALRJGAG4EXTTIEI2CGMZH3NCUQIQUTQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-composer'
  package(s) announced via the openSUSE-SU-2021:1289-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for php-composer fixes the following issues:

  - Require php-mbstring as requested in boo#1187416

  - Version 1.10.22

  * Security: Fixed command injection vulnerability in
         HgDriver/HgDownloader and hardened other VCS drivers and downloaders
         (GHSA-h5h8-pc6h-jvvx / CVE-2021-29472), boo#1185376

  - Version 1.10.21

  * Fixed support for new GitHub OAuth token format

  * Fixed processes silently ignoring the CWD when it does not exist

  - Version 1.10.20

  * Fixed exclude-from-classmap causing regex issues when having too many
         paths

  * Fixed compatibility issue with Symfony 4/5

  - Version 1.10.17

  * Fixed Bitbucket API authentication issue

  * Fixed parsing of Composer 2 lock files breaking in some rare conditions

  - Version 1.10.16

  * Added warning to validate command for cases where packages provide/
         replace a package that they also require

  * Fixed JSON schema validation issue with PHPStorm

  * Fixed symlink handling in archive command

  - Version 1.10.15

  * Fixed path repo version guessing issue

  - Version 1.10.14

  * Fixed version guesser to look at remote branches as well as local
         ones

  * Fixed path repositories version guessing to handle edge cases where
         version is different from the VCS-guessed version

  * Fixed COMPOSER env var causing issues when combined with the global
         command

  * Fixed a few issues dealing with PHP without openssl extension (not
         recommended at all but sometimes needed for testing)

  - Version 1.10.13

  * Fixed regressions with old version validation

  * Fixed invalid root aliases not being reported

  - Version 1.10.12

  * Fixed regressions with old version validation

  - Version 1.10.11

  * Fixed more PHP 8 compatibility issues

  * Fixed regression in handling of CTRL-C when xdebug is loaded

  * Fixed status handling of broken symlinks

  - Version 1.10.10

  * Fixed create-project not triggering events while installing the root
         package

  * Fixed PHP 8 compatibility issue

  * Fixed self-update to avoid automatically upgrading to the next major
         version once it becomes stable

  - Version 1.10.9

  * Fixed Bitbucket redirect loop when credentials are outdated

  * Fixed GitLab auth prompt wording

  * Fixed self-update handling of files requiring admin permissions to
         write to on Windows (it now does a UAC prompt)

  * Fixed parsing issues in fu ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'php-composer' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"php-composer", rpm:"php-composer~1.10.22~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
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