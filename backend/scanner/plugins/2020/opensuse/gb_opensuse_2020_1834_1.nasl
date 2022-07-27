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
  script_oid("1.3.6.1.4.1.25623.1.0.853557");
  script_version("2020-11-06T08:04:05+0000");
  script_cve_id("CVE-2018-19387", "CVE-2020-27347");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-11-06 11:47:26 +0000 (Fri, 06 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-06 04:01:10 +0000 (Fri, 06 Nov 2020)");
  script_name("openSUSE: Security Advisory for tmux (openSUSE-SU-2020:1834-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.2|openSUSELeap15\.1)");

  script_xref(name:"openSUSE-SU", value:"2020:1834-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-11/msg00022.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tmux'
  package(s) announced via the openSUSE-SU-2020:1834-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tmux fixes the following issues:

  - Update to version 3.1c

  * Fix a stack overflow on colon-separated CSI parsing. boo#1178263
  CVE-2020-27347

  - tmux 3.1b:

  * Fix crash when allow-rename ison and an empty name is set

  - tmux 3.1a:

  * Do not close stdout prematurely in control mode since it is needed to
  print exit messages. Prevents hanging when detaching with iTerm2

  - includes changes between 3.1-rc1 and 3.1:

  * Only search the visible part of the history when marking
  (highlighting) search terms. This is much faster than searching the
  whole history and solves problems with large histories. The count of
  matches shown is now the visible matches rather than all matches

  * Search using regular expressions in copy mode. search-forward and
  search-backward use regular expressions by default, the incremental
  versions do not

  * Turn off mouse mode 1003 as well as the rest when exiting

  * Add selection_active format for when the selection is present but not
  moving with the cursor

  * Fix dragging with modifier keys, so binding keys such as
  C-MouseDrag1Pane and C-MouseDragEnd1Pane now work

  * Add -a to list-keys to also list keys without notes with -N

  * Do not jump to next word end if already on a word end when selecting a
  word, fixes select-word with single character words and vi(1) keys

  * Fix top and bottom pane calculation with pane border status enabled

  - Update to v3.1-rc

  * Please see the included CHANGES file

  - Fix tmux completion

  - Update to v3.0a

  * A lot of changes since v2.9a, please see the included CHANGES file.

  - Update to v2.9a

  - Fix bugs in select-pane and the main-horizontal and main-vertical
  layouts.

  - Add trailing newline to tmpfiles.d/tmux.conf. On newer systems (such as
  Leap 15.1), the lack of a trailing newline appears to cause the
  directory to not be created. This is only evident on setups where /run
  is an actual tmpfs (on btrfs-root installs, /run is a btrfs subvolume
  and thus /run/tmux is persistent across reboots).

  - Update to version 2.9

  * Add format variables for the default formats in the various modes
  (tree_mode_format and so on) and add a -a flag to display-message to
  list variables with values.

  * Add a -v flag to display-message to show verbose messages as the
  format is parsed, this allows formats to be debugged

  * Add support for HPA (\033[`).

  * Add support for origin mode (\033[?6h).

  * No longer clear history on RIS.

  * Extend the #[] style syntax and use that together with previous format
  changes to allow the status line to be entirely config ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'tmux' package(s) on openSUSE Leap 15.2, openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"tmux", rpm:"tmux~3.1c~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tmux-debuginfo", rpm:"tmux-debuginfo~3.1c~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tmux-debugsource", rpm:"tmux-debugsource~3.1c~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"tmux", rpm:"tmux~3.1c~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tmux-debuginfo", rpm:"tmux-debuginfo~3.1c~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tmux-debugsource", rpm:"tmux-debugsource~3.1c~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
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