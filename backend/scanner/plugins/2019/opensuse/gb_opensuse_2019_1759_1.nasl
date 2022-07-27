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
  script_oid("1.3.6.1.4.1.25623.1.0.852630");
  script_version("2019-07-25T11:54:35+0000");
  script_cve_id("CVE-2019-12735");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-25 11:54:35 +0000 (Thu, 25 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-22 02:01:25 +0000 (Mon, 22 Jul 2019)");
  script_name("openSUSE Update for neovim openSUSE-SU-2019:1759-1 (neovim)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-07/msg00034.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'neovim'
  package(s) announced via the openSUSE-SU-2019:1759_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for neovim fixes the following issues:

  neovim was updated to version 0.3.7:

  * CVE-2019-12735: source should check sandbox (boo#1137443)

  * genappimage.sh: migrate to linuxdeploy

  Version Update to version 0.3.5:

  * options: properly reset directories on 'autochdir'

  * Remove MSVC optimization workaround for SHM_ALL

  * Make SHM_ALL to a variable instead of a compound literal #define

  * doc: mention 'pynvim' module rename

  * screen: don't crash when drawing popupmenu with 'rightleft' option

  * look-behind match may use the wrong line number

  * :terminal : set topline based on window height

  * :recover : Fix crash on non-existent *.swp

  Version Update to version 0.3.4:

  * test: add tests for conceal cursor movement

  * display: unify ursorline and concealcursor redraw logic

  Version Update to version 0.3.3:

  * health/provider: Check for available pynvim when neovim mod is missing

  * python#CheckForModule: Use the given module string instead of
  hard-coding pynvim

  * (health.provider)/python: Import the neovim, rather than pynvim, module

  * TUI: Konsole DECSCUSR fixup

  Version Update to version 0.3.2:-

  * Features

  - clipboard: support Custom VimL functions (#9304)

  - win/TUI: improve terminal/console support (#9401)

  - startup: Use $XDG_CONFIG_DIRS/nvim/sysinit.vim if exists (#9077)

  - support mapping in more places (#9299)

  - diff/highlight: show underline for low-priority CursorLine (#9028)

  - signs: Add 'nuhml' argument (#9113)

  - clipboard: support Wayland (#9230)

  - TUI: add support for undercurl and underline color (#9052)

  - man.vim: soft (dynamic) wrap (#9023)

  * API

  - API: implement object namespaces (#6920)

  - API: implement nvim_win_set_buf() (#9100)

  - API: virtual text annotations (nvim_buf_set_virtual_text) (#8180)

  - API: add nvim_buf_is_loaded() (#8660)

  - API: nvm_buf_get_offset_for_line (#8221)

  - API/UI: ext_newgrid, ext_histate (#8221)

  * UI

  - TUI: use BCE again more often (smoother resize) (#8806)

  - screen: add missing status redraw when redraw_later(CLEAR) was used
  (#9315)

  - TUI: clip invalid regions on resize (#8779)

  - TUI: improvements for scrolling and clearing (#9193)

  - TUI: disable clearing almost everywhere (#9143)

  - TUI: always use safe cursor movement after resize (#9079)

  - ui_options: also send when starting or from OptionSet (#9211)

  - TUI: Avoid reset_color_cursor_color in old VTE (#9191)

  - Don't erase screen on :hi Normal during startup (#9021)

  - TUI: Hint wrapped lines to terminals (#8915)

  * FIXES

  - RPC: turn errors from async calls into notifications

  - TUI: R ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'neovim' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"neovim", rpm:"neovim~0.3.7~lp150.13.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"neovim-debuginfo", rpm:"neovim-debuginfo~0.3.7~lp150.13.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"neovim-debugsource", rpm:"neovim-debugsource~0.3.7~lp150.13.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"neovim-lang", rpm:"neovim-lang~0.3.7~lp150.13.1", rls:"openSUSELeap15.0"))) {
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
