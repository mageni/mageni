###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_1833_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for ImageMagick openSUSE-SU-2016:1833-1 (ImageMagick)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851368");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-08-02 10:55:29 +0530 (Tue, 02 Aug 2016)");
  script_cve_id("CVE-2014-9805", "CVE-2014-9806", "CVE-2014-9807", "CVE-2014-9808",
                "CVE-2014-9809", "CVE-2014-9810", "CVE-2014-9811", "CVE-2014-9812",
                "CVE-2014-9813", "CVE-2014-9814", "CVE-2014-9815", "CVE-2014-9816",
                "CVE-2014-9817", "CVE-2014-9818", "CVE-2014-9819", "CVE-2014-9820",
                "CVE-2014-9821", "CVE-2014-9822", "CVE-2014-9823", "CVE-2014-9824",
                "CVE-2014-9825", "CVE-2014-9826", "CVE-2014-9828", "CVE-2014-9829",
                "CVE-2014-9830", "CVE-2014-9831", "CVE-2014-9832", "CVE-2014-9833",
                "CVE-2014-9834", "CVE-2014-9835", "CVE-2014-9836", "CVE-2014-9837",
                "CVE-2014-9838", "CVE-2014-9839", "CVE-2014-9840", "CVE-2014-9841",
                "CVE-2014-9842", "CVE-2014-9843", "CVE-2014-9844", "CVE-2014-9845",
 		"CVE-2014-9846", "CVE-2014-9847", "CVE-2014-9848", "CVE-2014-9849",
		"CVE-2014-9850", "CVE-2014-9851", "CVE-2014-9852", "CVE-2014-9853",
		"CVE-2014-9854", "CVE-2015-8894", "CVE-2015-8895", "CVE-2015-8896",
 		"CVE-2015-8897", "CVE-2015-8898", "CVE-2015-8900", "CVE-2015-8901",
		"CVE-2015-8902", "CVE-2015-8903", "CVE-2016-4562", "CVE-2016-4563",
		"CVE-2016-4564", "CVE-2016-5687", "CVE-2016-5688", "CVE-2016-5689",
		"CVE-2016-5690", "CVE-2016-5691", "CVE-2016-5841", "CVE-2016-5842");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for ImageMagick openSUSE-SU-2016:1833-1 (ImageMagick)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"ImageMagick was updated to fix 66 security issues.

  These security issues were fixed:

  - CVE-2014-9810: SEGV in dpx file handler. (bsc#983803).

  - CVE-2014-9811: Crash in xwd file handler (bsc#984032).

  - CVE-2014-9812: NULL pointer dereference in ps file handling (bsc#984137).

  - CVE-2014-9813: Crash on corrupted viff file (bsc#984035).

  - CVE-2014-9814: NULL pointer dereference in wpg file handling
  (bsc#984193).

  - CVE-2014-9815: Crash on corrupted wpg file (bsc#984372).

  - CVE-2014-9816: Out of bound access in viff image (bsc#984398).

  - CVE-2014-9817: Heap buffer overflow in pdb file handling (bsc#984400).

  - CVE-2014-9818: Out of bound access on malformed sun file (bsc#984181).

  - CVE-2014-9819: Heap overflow in palm files (bsc#984142).

  - CVE-2014-9830: Handling of corrupted sun file (bsc#984135).

  - CVE-2014-9831: Handling of corrupted wpg file (bsc#984375).

  - CVE-2014-9850: Incorrect thread limit logic (bsc#984149).

  - CVE-2014-9851: Crash when parsing resource block (bsc#984160).

  - CVE-2014-9852: Incorrect usage of object after it has been destroyed
  (bsc#984191).

  - CVE-2014-9853: Memory leak in rle file handling (bsc#984408).

  - CVE-2015-8902: PDB file DoS (CPU consumption) (bsc#983253).

  - CVE-2015-8903: Denial of service (cpu) in vicar (bsc#983259).

  - CVE-2015-8900: HDR file DoS (endless loop) (bsc#983232).

  - CVE-2015-8901: MIFF file DoS (endless loop) (bsc#983234).

  - CVE-2016-5688: Various invalid memory reads in ImageMagick WPG
  (bsc#985442).

  - CVE-2014-9834: Heap overflow in pict file (bsc#984436).

  - CVE-2014-9806: Prevent leak of file descriptor due to corrupted file.
  (bsc#983774).

  - CVE-2016-5687: Out of bounds read in DDS coder (bsc#985448).

  - CVE-2014-9838: Out of memory crash in magick/cache.c (bsc#984370).

  - CVE-2014-9854: Filling memory during identification of TIFF image
  (bsc#984184).

  - CVE-2015-8898: Prevent null pointer access in magick/constitute.c
  (bsc#983746).

  - CVE-2014-9833: Heap overflow in psd file (bsc#984406).

  - CVE-2015-8894: Double free in coders/tga.c:221 (bsc#983523).

  - CVE-2015-8895: Integer and Buffer overflow in coders/icon.c (bsc#983527).

  - CVE-2015-8896: Double free / integer truncation issue in
  coders/pict.c:2000 (bsc#983533).

  - CVE-2015-8897: Out of bounds error in SpliceImage (bsc#983739).

  - CVE-2016-5690: Bad foor loop in  DCM coder (bsc#985451).

  - CVE-2016-5691: Checks for pixel.red/green/blue in dcm coder (bsc#985456).

  - CVE-2014-9836: Crash in xpm file handling (bsc#984023).

  - CVE-2014-9808: SEGV due to corrupted dpc images. (bsc#983796).

  - CVE-2014-9821: Avo ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"ImageMagick on openSUSE Leap 42.1");
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

  if ((res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~6.8.8.1~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-debuginfo", rpm:"ImageMagick-debuginfo~6.8.8.1~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-debugsource", rpm:"ImageMagick-debugsource~6.8.8.1~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-devel", rpm:"ImageMagick-devel~6.8.8.1~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-extra", rpm:"ImageMagick-extra~6.8.8.1~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-extra-debuginfo", rpm:"ImageMagick-extra-debuginfo~6.8.8.1~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagick++-6_Q16-3", rpm:"libMagick++-6_Q16-3~6.8.8.1~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagick++-6_Q16-3-debuginfo", rpm:"libMagick++-6_Q16-3-debuginfo~6.8.8.1~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagick++-devel", rpm:"libMagick++-devel~6.8.8.1~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagickCore-6_Q16-1-debuginfo", rpm:"libMagickCore-6_Q16-1-debuginfo~6.8.8.1~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagickWand-6_Q16-1-debuginfo", rpm:"libMagickWand-6_Q16-1-debuginfo~6.8.8.1~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-PerlMagick", rpm:"perl-PerlMagick~6.8.8.1~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-PerlMagick-debuginfo", rpm:"perl-PerlMagick-debuginfo~6.8.8.1~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-devel-32bit", rpm:"ImageMagick-devel-32bit~6.8.8.1~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagick++-6_Q16-3-32bit", rpm:"libMagick++-6_Q16-3-32bit~6.8.8.1~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagick++-6_Q16-3-debuginfo-32bit", rpm:"libMagick++-6_Q16-3-debuginfo-32bit~6.8.8.1~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagick++-devel-32bit", rpm:"libMagick++-devel-32bit~6.8.8.1~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagickCore-6_Q16-1-32bit", rpm:"libMagickCore-6_Q16-1-32bit~6.8.8.1~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagickCore-6_Q16-1-debuginfo-32bit", rpm:"libMagickCore-6_Q16-1-debuginfo-32bit~6.8.8.1~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagickWand-6_Q16-1-32bit", rpm:"libMagickWand-6_Q16-1-32bit~6.8.8.1~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagickWand-6_Q16-1-debuginfo-32bit", rpm:"libMagickWand-6_Q16-1-debuginfo-32bit~6.8.8.1~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-doc", rpm:"ImageMagick-doc~6.8.8.1~15.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
