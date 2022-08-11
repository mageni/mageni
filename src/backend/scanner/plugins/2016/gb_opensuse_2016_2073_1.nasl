###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_2073_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for GraphicsMagick openSUSE-SU-2016:2073-1 (GraphicsMagick)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851385");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-08-16 05:43:14 +0200 (Tue, 16 Aug 2016)");
  script_cve_id("CVE-2014-9805", "CVE-2014-9807", "CVE-2014-9809", "CVE-2014-9815",
                "CVE-2014-9817", "CVE-2014-9819", "CVE-2014-9820", "CVE-2014-9831",
                "CVE-2014-9834", "CVE-2014-9835", "CVE-2014-9837", "CVE-2014-9839",
                "CVE-2014-9845", "CVE-2014-9846", "CVE-2014-9853", "CVE-2015-8894",
                "CVE-2015-8896", "CVE-2016-2317", "CVE-2016-2318", "CVE-2016-5240",
                "CVE-2016-5241", "CVE-2016-5688");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for GraphicsMagick openSUSE-SU-2016:2073-1 (GraphicsMagick)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'GraphicsMagick'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for GraphicsMagick fixes the following issues:

  - CVE-2014-9805: SEGV due to a corrupted pnm file (boo#983752)

  - CVE-2016-5240: SVG converting issue resulting in DoS (endless loop)
  (boo#983309)

  - CVE-2016-5241: Arithmetic exception (div by 0) in SVG conversion
  (boo#983455)

  - CVE-2014-9846: Overflow in rle file (boo#983521)

  - CVE-2015-8894: Double free in TGA code (boo#983523)

  - CVE-2015-8896: Double free / integer truncation issue (boo#983533)

  - CVE-2014-9807: Double free in pdb coder (boo#983794)

  - CVE-2014-9809: SEGV due to corrupted xwd images (boo#983799)

  - CVE-2014-9819: Heap overflow in palm files (boo#984142)

  - CVE-2014-9835: Heap overflow in wpf file (boo#984145)

  - CVE-2014-9831: Issues handling of corrupted wpg file (boo#984375)

  - CVE-2014-9820: heap overflow in xpm files (boo#984150)

  - CVE-2014-9837: Additional PNM sanity checks (boo#984166)

  - CVE-2014-9815: Crash on corrupted wpg file (boo#984372)

  - CVE-2014-9839: Theoretical out of bound access in via color maps
  (boo#984379)

  - CVE-2014-9845: Crash due to corrupted dib file (boo#984394)

  - CVE-2014-9817: Heap buffer overflow in pdb file handling (boo#984400)

  - CVE-2014-9853: Memory leak in rle file handling (boo#984408)

  - CVE-2014-9834: Heap overflow in pict file (boo#984436)

  - CVE-2016-5688: Various invalid memory reads in ImageMagick WPG
  (boo#985442)

  - CVE-2016-2317: Multiple vulnerabilities when parsing and processing SVG
  files (boo#965853)

  - CVE-2016-2318: Multiple vulnerabilities when parsing and processing SVG
  files (boo#965853)");
  script_tag(name:"affected", value:"GraphicsMagick on openSUSE Leap 42.1");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.1")
{

  if ((res = isrpmvuln(pkg:"GraphicsMagick", rpm:"GraphicsMagick~1.3.21~11.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"GraphicsMagick-debuginfo", rpm:"GraphicsMagick-debuginfo~1.3.21~11.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"GraphicsMagick-debugsource", rpm:"GraphicsMagick-debugsource~1.3.21~11.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"GraphicsMagick-devel", rpm:"GraphicsMagick-devel~1.3.21~11.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick++-Q16-11", rpm:"libGraphicsMagick++-Q16-11~1.3.21~11.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick++-Q16-11-debuginfo", rpm:"libGraphicsMagick++-Q16-11-debuginfo~1.3.21~11.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick++-devel", rpm:"libGraphicsMagick++-devel~1.3.21~11.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick-Q16-3", rpm:"libGraphicsMagick-Q16-3~1.3.21~11.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick-Q16-3-debuginfo", rpm:"libGraphicsMagick-Q16-3-debuginfo~1.3.21~11.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick3-config", rpm:"libGraphicsMagick3-config~1.3.21~11.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagickWand-Q16-2", rpm:"libGraphicsMagickWand-Q16-2~1.3.21~11.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagickWand-Q16-2-debuginfo", rpm:"libGraphicsMagickWand-Q16-2-debuginfo~1.3.21~11.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-GraphicsMagick", rpm:"perl-GraphicsMagick~1.3.21~11.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-GraphicsMagick-debuginfo", rpm:"perl-GraphicsMagick-debuginfo~1.3.21~11.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
