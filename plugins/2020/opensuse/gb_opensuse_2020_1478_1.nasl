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
  script_oid("1.3.6.1.4.1.25623.1.0.853439");
  script_version("2020-09-28T10:54:24+0000");
  script_cve_id("CVE-2020-24614");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-09-29 10:01:49 +0000 (Tue, 29 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-21 03:00:42 +0000 (Mon, 21 Sep 2020)");
  script_name("openSUSE: Security Advisory for fossil (openSUSE-SU-2020:1478-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.2|openSUSELeap15\.1)");

  script_xref(name:"openSUSE-SU", value:"2020:1478-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00065.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fossil'
  package(s) announced via the openSUSE-SU-2020:1478-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for fossil fixes the following issues:

  - fossil 2.12.1:

  * CVE-2020-24614: Remote authenticated users with check-in or
  administrative privileges could have executed arbitrary code
  [boo#1175760]

  * Security fix in the 'fossil git export' command. New 'safety-net'
  features were added to prevent similar problems in the future.

  * Enhancements to the graph display for cases when there are many
  cherry-pick merges into a single check-in. Example

  * Enhance the fossil open command with the new --workdir option and the
  ability to accept a URL as the repository name, causing the remote
  repository to be cloned automatically. Do not allow 'fossil open' to
  open in a non-empty working directory unless the --keep option or the
  new --force option is used.

  * Enhance the markdown formatter to more closely follow the CommonMark
  specification with regard to text highlighting. Underscores in the
  middle of identifiers (ex: fossil_printf()) no longer need to be
  escaped.

  * The markdown-to-html translator can prevent unsafe HTML (for example:
  <script>) on user-contributed pages like forum and tickets and wiki.
  The admin can adjust this behavior using the safe-html setting on the
  Admin/Wiki page. The default is to disallow unsafe HTML everywhere.

  * Added the 'collapse' and 'expand' capability for long forum posts.

  * The 'fossil remote' command now has options for specifying multiple
  persistent remotes with symbolic names. Currently
  only one remote can be used at a time, but that might change in the
  future.

  * Add the 'Remember me?' checkbox on the login page. Use a session
  cookie for the login if it is not checked.

  * Added the experimental 'fossil hook' command for managing 'hook
  scripts' that run before checkin or after a push.

  * Enhance the fossil revert command so that it is able to revert all
  files beneath a directory.

  * Add the fossil bisect skip command.

  * Add the fossil backup command.

  * Enhance fossil bisect ui so that it shows all unchecked check-ins in
  between the innermost 'good' and 'bad' check-ins.

  * Added the --reset flag to the 'fossil add', 'fossil rm', and 'fossil
  addremove' commands.

  * Added the '--min N' and '--logfile FILENAME' flags to the backoffice
  command, as well as other enhancements to make the backoffice command
  a viable replacement for automatic backoffice. Other incremental
  backoffice improvements.

  * Added the /fileedit page, which allows editing of text files
  online. Requires explicit activation by a setup user.

  * Translate built-in help text into HTML for display o ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'fossil' package(s) on openSUSE Leap 15.2, openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"fossil", rpm:"fossil~2.12.1~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fossil-debuginfo", rpm:"fossil-debuginfo~2.12.1~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fossil-debugsource", rpm:"fossil-debugsource~2.12.1~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"fossil", rpm:"fossil~2.12.1~lp151.3.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fossil-debuginfo", rpm:"fossil-debuginfo~2.12.1~lp151.3.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fossil-debugsource", rpm:"fossil-debugsource~2.12.1~lp151.3.6.1", rls:"openSUSELeap15.1"))) {
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