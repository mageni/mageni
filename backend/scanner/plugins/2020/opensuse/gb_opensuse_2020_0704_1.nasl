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
  script_oid("1.3.6.1.4.1.25623.1.0.853175");
  script_version("2020-05-27T04:05:03+0000");
  script_cve_id("CVE-2018-6942");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-05-27 09:35:59 +0000 (Wed, 27 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-24 03:00:37 +0000 (Sun, 24 May 2020)");
  script_name("openSUSE: Security Advisory for freetype2 (openSUSE-SU-2020:0704-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00054.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freetype2'
  package(s) announced via the openSUSE-SU-2020:0704-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for freetype2 to version 2.10.1 fixes the following issues:

  Security issue fixed:

  - CVE-2018-6942: Fixed a NULL pointer dereference within ttinerp.c
  (bsc#1079603).

  Non-security issues fixed:

  - Update to version 2.10.1

  * The bytecode hinting of OpenType variation fonts was flawed, since the
  data in the `CVAR' table wasn't correctly applied.

  * Auto-hinter support for Mongolian.

  * The handling of  the default character in PCF fonts as  introduced in
  version 2.10.0 was partially broken, causing premature abortion
  of charmap iteration for many fonts.

  * If  `FT_Set_Named_Instance' was  called  with  the same  arguments
  twice in a row, the function  returned an incorrect error code the
  second time.

  * Direct   rendering   using  FT_RASTER_FLAG_DIRECT   crashed   (bug
  introduced in version 2.10.0).

  * Increased  precision  while  computing  OpenType  font   variation
  instances.

  * The  flattening  algorithm of  cubic  Bezier  curves was  slightly
  changed to make  it faster.  This can cause  very subtle rendering
  changes, which aren't noticeable by the eye, however.

  * The  auto-hinter  now  disables hinting  if there  are blue  zones
  defined for a `style' (i.e., a certain combination of a script and its
  related typographic features) but the font doesn't contain any
  characters needed to set up at least one blue zone.

  - Add tarball signatures and freetype2.keyring

  - Update to version 2.10.0

  * A bunch of new functions has been added to access and process
  COLR/CPAL data of OpenType fonts with color-layered glyphs.

  * As a GSoC 2018 project, Nikhil Ramakrishnan completely
  overhauled and modernized the API reference.

  * The logic for computing the global ascender, descender, and height of
  OpenType fonts has been slightly adjusted for consistency.

  * `TT_Set_MM_Blend' could fail if called repeatedly with the same
  arguments.

  * The precision of handling deltas in Variation Fonts has been
  increased.The problem did only show up with multidimensional
  designspaces.

  * New function `FT_Library_SetLcdGeometry' to set up the geometry
  of LCD subpixels.

  * FreeType now uses the `defaultChar' property of PCF fonts to set the
  glyph for  the undefined  character  at glyph  index 0  (as FreeType
  already does for all other supported font formats).  As a consequence,
  the order of glyphs of a PCF font if accessed with  FreeType can be
  different now compared to previous versions. This change doesn't
  affect PCF font access with cmaps.

  * `FT_Select_Charmap' has been changed to allow  parameter value
  `FT_ENCODING_NONE' ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'freetype2' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"freetype2-debugsource", rpm:"freetype2-debugsource~2.10.1~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype2-devel", rpm:"freetype2-devel~2.10.1~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6", rpm:"libfreetype6~2.10.1~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-debuginfo", rpm:"libfreetype6-debuginfo~2.10.1~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype2-devel-32bit", rpm:"freetype2-devel-32bit~2.10.1~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ft2demos", rpm:"ft2demos~2.10.1~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ftbench", rpm:"ftbench~2.10.1~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ftdiff", rpm:"ftdiff~2.10.1~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ftdump", rpm:"ftdump~2.10.1~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ftgamma", rpm:"ftgamma~2.10.1~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ftgrid", rpm:"ftgrid~2.10.1~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ftinspect", rpm:"ftinspect~2.10.1~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ftlint", rpm:"ftlint~2.10.1~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ftmulti", rpm:"ftmulti~2.10.1~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ftstring", rpm:"ftstring~2.10.1~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ftvalid", rpm:"ftvalid~2.10.1~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ftview", rpm:"ftview~2.10.1~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-32bit", rpm:"libfreetype6-32bit~2.10.1~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-32bit-debuginfo", rpm:"libfreetype6-32bit-debuginfo~2.10.1~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype2-profile-tti35", rpm:"freetype2-profile-tti35~2.10.1~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
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