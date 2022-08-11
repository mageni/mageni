###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_0420_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for freetype2 openSUSE-SU-2018:0420-1 (freetype2)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851700");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-02-14 08:41:15 +0100 (Wed, 14 Feb 2018)");
  script_cve_id("CVE-2016-10244", "CVE-2017-7864", "CVE-2017-8105", "CVE-2017-8287");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for freetype2 openSUSE-SU-2018:0420-1 (freetype2)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'freetype2'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for freetype2 fixes the following security issues:

  - CVE-2016-10244: Make sure that the parse_charstrings function in
  type1/t1load.c does ensure that a font contains a glyph name to prevent
  a DoS through a heap-based buffer over-read or possibly have unspecified
  other impact via a crafted file (bsc#1028103)

  - CVE-2017-8105: Fix an out-of-bounds write caused by a heap-based buffer
  overflow related to the t1_decoder_parse_charstrings function in
  psaux/t1decode.ca (bsc#1035807)

  - CVE-2017-8287: an out-of-bounds write caused by a heap-based buffer
  overflow related to the t1_builder_close_contour function in
  psaux/psobjs.c (bsc#1036457)

  - Fix several integer overflow issues in truetype/ttinterp.c (bsc#1079600)

  This update was imported from the SUSE:SLE-12-SP2:Update update project.");
  script_tag(name:"affected", value:"freetype2 on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-02/msg00016.html");
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

  if ((res = isrpmvuln(pkg:"freetype2-debugsource", rpm:"freetype2-debugsource~2.6.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2-devel", rpm:"freetype2-devel~2.6.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ft2demos", rpm:"ft2demos~2.6.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreetype6", rpm:"libfreetype6~2.6.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreetype6-debuginfo", rpm:"libfreetype6-debuginfo~2.6.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freetype2-devel-32bit", rpm:"freetype2-devel-32bit~2.6.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreetype6-32bit", rpm:"libfreetype6-32bit~2.6.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreetype6-debuginfo-32bit", rpm:"libfreetype6-debuginfo-32bit~2.6.3~5.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
