###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_0734_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for SDL2, openSUSE-SU-2018:0734-1 (SDL2,)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851720");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-03-19 08:26:15 +0100 (Mon, 19 Mar 2018)");
  script_cve_id("CVE-2017-12122", "CVE-2017-14440", "CVE-2017-14441", "CVE-2017-14442",
                "CVE-2017-14448", "CVE-2017-14449", "CVE-2017-14450");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for SDL2, openSUSE-SU-2018:0734-1 (SDL2, )");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'SDL2.'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for SDL2 and SDL2_image fixes the following issues:

  - CVE-2017-14441: Code execution in the ICO image rendering (bsc#1084282).

  - CVE-2017-14440: Potential code execution in the ILBM image rendering
  functionality (bsc#1084257).

  - CVE-2017-12122: Potential code execution in the ILBM image rendering
  fuctionality (bsc#1084256).

  - CVE-2017-14448: Heap buffer overflow in the XCF image rendering
  functionality (bsc#1084303).

  - CVE-2017-14449: Double-Free in the XCF image rendering (bsc#1084297).

  - CVE-2017-14442: Stack buffer overflow the BMP image rendering
  functionality (bsc#1084304).

  - CVE-2017-14450: Buffer overflow in the GIF image parsing (bsc#1084288).

  Bug fixes:

  - boo#1025413: Add dbus-ime.diff and build with fcitx.");
  script_tag(name:"affected", value:"SDL2, on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-03/msg00047.html");
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

  if ((res = isrpmvuln(pkg:"SDL2-debugsource", rpm:"SDL2-debugsource~2.0.8~18.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"SDL2_image-debugsource", rpm:"SDL2_image-debugsource~2.0.3~13.10.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libSDL2-2_0-0", rpm:"libSDL2-2_0-0~2.0.8~18.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libSDL2-2_0-0-debuginfo", rpm:"libSDL2-2_0-0-debuginfo~2.0.8~18.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libSDL2-devel", rpm:"libSDL2-devel~2.0.8~18.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libSDL2_image-2_0-0", rpm:"libSDL2_image-2_0-0~2.0.3~13.10.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libSDL2_image-2_0-0-debuginfo", rpm:"libSDL2_image-2_0-0-debuginfo~2.0.3~13.10.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libSDL2_image-devel", rpm:"libSDL2_image-devel~2.0.3~13.10.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libSDL2-2_0-0-32bit", rpm:"libSDL2-2_0-0-32bit~2.0.8~18.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libSDL2-2_0-0-debuginfo-32bit", rpm:"libSDL2-2_0-0-debuginfo-32bit~2.0.8~18.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libSDL2-devel-32bit", rpm:"libSDL2-devel-32bit~2.0.8~18.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libSDL2_image-2_0-0-32bit", rpm:"libSDL2_image-2_0-0-32bit~2.0.3~13.10.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libSDL2_image-2_0-0-debuginfo-32bit", rpm:"libSDL2_image-2_0-0-debuginfo-32bit~2.0.3~13.10.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libSDL2_image-devel-32bit", rpm:"libSDL2_image-devel-32bit~2.0.3~13.10.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
