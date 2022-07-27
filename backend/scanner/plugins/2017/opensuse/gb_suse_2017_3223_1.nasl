###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_3223_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for GraphicsMagick openSUSE-SU-2017:3223-1 (GraphicsMagick)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851657");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-12-07 07:41:17 +0100 (Thu, 07 Dec 2017)");
  script_cve_id("CVE-2017-11640", "CVE-2017-13737", "CVE-2017-14341", "CVE-2017-14342", "CVE-2017-16545", "CVE-2017-16546", "CVE-2017-16669");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for GraphicsMagick openSUSE-SU-2017:3223-1 (GraphicsMagick)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'GraphicsMagick'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for GraphicsMagick fixes the following issues:

  Security issues fixed:

  - CVE-2017-16546: Fix ReadWPGImage function in coders/wpg.c that could
  lead to a denial of service (bsc#1067181).

  - CVE-2017-14342: Fix a memory exhaustion vulnerability in ReadWPGImage in
  coders/wpg.c that could lead to a denial of service (bsc#1058485).

  - CVE-2017-16669: Fix coders/wpg.c that allows remote attackers to cause a
  denial of service via crafted files (bsc#1067409).

  - CVE-2017-16545: Fix the ReadWPGImage function in coders/wpg.c as a
  validation problems could lead to a denial of service (bsc#1067184).

  - CVE-2017-14341: Fix infinite loop in the ReadWPGImage function
  (bsc#1058637).

  - CVE-2017-13737: Fix invalid free in the MagickFree function in
  magick/memory.c (tiff.c) (bsc#1056162).

  - CVE-2017-11640: Fix NULL pointer deref in WritePTIFImage() in
  coders/tiff.c (bsc#1050632).");
  script_tag(name:"affected", value:"GraphicsMagick on openSUSE Leap 42.3, openSUSE Leap 42.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.2|openSUSELeap42\.3)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.2")
{

  if ((res = isrpmvuln(pkg:"GraphicsMagick", rpm:"GraphicsMagick~1.3.25~11.44.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"GraphicsMagick-debuginfo", rpm:"GraphicsMagick-debuginfo~1.3.25~11.44.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"GraphicsMagick-debugsource", rpm:"GraphicsMagick-debugsource~1.3.25~11.44.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"GraphicsMagick-devel", rpm:"GraphicsMagick-devel~1.3.25~11.44.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick++-Q16-12", rpm:"libGraphicsMagick++-Q16-12~1.3.25~11.44.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick++-Q16-12-debuginfo", rpm:"libGraphicsMagick++-Q16-12-debuginfo~1.3.25~11.44.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick++-devel", rpm:"libGraphicsMagick++-devel~1.3.25~11.44.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick-Q16-3", rpm:"libGraphicsMagick-Q16-3~1.3.25~11.44.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick-Q16-3-debuginfo", rpm:"libGraphicsMagick-Q16-3-debuginfo~1.3.25~11.44.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick3-config", rpm:"libGraphicsMagick3-config~1.3.25~11.44.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagickWand-Q16-2", rpm:"libGraphicsMagickWand-Q16-2~1.3.25~11.44.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagickWand-Q16-2-debuginfo", rpm:"libGraphicsMagickWand-Q16-2-debuginfo~1.3.25~11.44.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-GraphicsMagick", rpm:"perl-GraphicsMagick~1.3.25~11.44.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-GraphicsMagick-debuginfo", rpm:"perl-GraphicsMagick-debuginfo~1.3.25~11.44.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"GraphicsMagick", rpm:"GraphicsMagick~1.3.25~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"GraphicsMagick-debuginfo", rpm:"GraphicsMagick-debuginfo~1.3.25~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"GraphicsMagick-debugsource", rpm:"GraphicsMagick-debugsource~1.3.25~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"GraphicsMagick-devel", rpm:"GraphicsMagick-devel~1.3.25~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick++-Q16-12", rpm:"libGraphicsMagick++-Q16-12~1.3.25~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick++-Q16-12-debuginfo", rpm:"libGraphicsMagick++-Q16-12-debuginfo~1.3.25~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick++-devel", rpm:"libGraphicsMagick++-devel~1.3.25~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick-Q16-3", rpm:"libGraphicsMagick-Q16-3~1.3.25~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick-Q16-3-debuginfo", rpm:"libGraphicsMagick-Q16-3-debuginfo~1.3.25~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagick3-config", rpm:"libGraphicsMagick3-config~1.3.25~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagickWand-Q16-2", rpm:"libGraphicsMagickWand-Q16-2~1.3.25~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libGraphicsMagickWand-Q16-2-debuginfo", rpm:"libGraphicsMagickWand-Q16-2-debuginfo~1.3.25~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-GraphicsMagick", rpm:"perl-GraphicsMagick~1.3.25~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-GraphicsMagick-debuginfo", rpm:"perl-GraphicsMagick-debuginfo~1.3.25~44.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
