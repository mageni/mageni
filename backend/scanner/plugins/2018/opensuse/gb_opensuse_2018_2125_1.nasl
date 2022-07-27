###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2125_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for cinnamon openSUSE-SU-2018:2125-1 (cinnamon)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.851825");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-07-29 05:59:16 +0200 (Sun, 29 Jul 2018)");
  script_cve_id("CVE-2018-13054");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for cinnamon openSUSE-SU-2018:2125-1 (cinnamon)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'cinnamon'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for cinnamon fixes the following issues:

  Security issue fixed:

  - CVE-2018-13054: Fix symlink attack vulnerability (boo#1083067).

  Bug fixes:

  - Update to version 3.4.6 (changes since 3.4.4):

  * osdWindow.js: Always check the theme node on first showing - an
  actor's width isn't necessarily filled if it hasn't been explicitly
  set, causing the first few activations of the OSD to not show an
  accurate level bar.

  * cs_default: Fix an incorrect button label (but preserve translations).

  * main.js: Remove an obsolete Meta enum member reference.

  * workspace.js: Use our normal prototype init method.

  * workspace.js: Initialise WindowClone._zoomStep to 0.

  * slideshow-applet: Fix a translation.

  * cs_themes.py: Create the file '~/.icons/default/index.theme' and set
  the selected cursor theme inside of it. This ensures other (non-gtk)
  applications end up using the same theme (though they are required to
  be restarted for these changes to take effect).

  * keyboard-applet: Applet icon vanishes when moved in edit mode.

  * cinnamon-json-makepot: Add keyword option, change language used by
  xgettext to JavaScript.

  * expoThumbnail: Correct a couple of calls with mismatched argument
  counts.

  * window-list: Set AppMenuButtons unreactive during panel edit mode.

  * panel-launchers: Set PanelAppLaunchers unreactive during panel edit
  mode.

  * windows-quick-list: Fix argument warning.

  * Fix a reference to undefined actor._delegate warning.

  * ui/environment: Handle undefined actors in
  containerClass.prototype.add.

  * ui/cinnamonDBus: Handle null xlet objects in
  CinnamonDBus.highlightXlet.

  * deskletManager: Initialise some variables and remove the variables
  that were initialised, probable typo


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-767=1");
  script_tag(name:"affected", value:"cinnamon on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-07/msg00042.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"cinnamon", rpm:"cinnamon~3.4.6~2.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cinnamon-debuginfo", rpm:"cinnamon-debuginfo~3.4.6~2.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cinnamon-debugsource", rpm:"cinnamon-debugsource~3.4.6~2.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cinnamon-gschemas", rpm:"cinnamon-gschemas~3.4.6~2.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cinnamon-gschemas-branding-upstream", rpm:"cinnamon-gschemas-branding-upstream~3.4.6~2.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
