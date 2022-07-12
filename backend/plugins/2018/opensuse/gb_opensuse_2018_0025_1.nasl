###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_0025_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for ImageMagick openSUSE-SU-2018:0025-1 (ImageMagick)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851675");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-01-05 23:56:32 +0100 (Fri, 05 Jan 2018)");
  script_cve_id("CVE-2017-12563", "CVE-2017-12691", "CVE-2017-13061", "CVE-2017-13062",
                "CVE-2017-14042", "CVE-2017-14174", "CVE-2017-14343", "CVE-2017-15277",
                "CVE-2017-15281");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for ImageMagick openSUSE-SU-2018:0025-1 (ImageMagick)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:

  - security update (xcf.c):

  * CVE-2017-14343: Memory leak vulnerability in ReadXCFImage could lead
  to denial of service via a crafted file. CVE-2017-12691: The
  ReadOneLayer function in coders/xcf.c allows remote attackers to cause
  a denial of service (memory consumption) via a crafted file.
  [bsc#1058422]

  - security update (pnm.c):

  * CVE-2017-14042: A memory allocation failure was discovered in the
  ReadPNMImage function in coders/pnm.c and could lead to remote denial
  of service [bsc#1056550]

  - security update (psd.c):

  * CVE-2017-15281: ReadPSDImage allows remote attackers to cause a denial
  of service (application crash) or possibly have unspecified other
  impact via a crafted file [bsc#1063049]

  * CVE-2017-13061: A length-validation vulnerability was found in the
  function ReadPSDLayersInternal in coders/psd.c, which allows attackers
  to cause a denial of service (ReadPSDImage memory exhaustion) via a
  crafted file. [bsc#1055063]

  * CVE-2017-12563: A Memory exhaustion vulnerability was found in the
  function ReadPSDImage in coders/psd.c, which allows attackers to cause
  a denial of service. [bsc#1052460]

  * CVE-2017-14174: Due to a lack of an EOF check (End of File) in
  ReadPSDLayersInternal could cause huge CPU consumption, when a crafted
  PSD file, which claims a large 'length' field in the header but does
  not contain sufficient backing data, is provided, the loop over
  \'length\' would consume huge CPU resources, since there is no EOF
  check inside the loop.[bsc#1057723]

  - security update (meta.c):

  * CVE-2017-13062: Amemory leak vulnerability was found in the function
  formatIPTC in coders/meta.c, which allows attackers to cause a denial
  of service (WriteMETAImage memory consumption) via a crafted file
  [bsc#1055053]

  - security update (gif.c):

  * CVE-2017-15277: ReadGIFImage in coders/gif.c leaves the palette
  uninitialized when processing a GIF file that has neither a global nor
  local palette. If the affected product is used as a library loaded
  into a process that operates on interesting data, this data sometimes
  can be leaked via the uninitialized palette.[bsc#1063050]

  This update was imported from the SUSE:SLE-12:Update update project.");
  script_tag(name:"affected", value:"ImageMagick on openSUSE Leap 42.3, openSUSE Leap 42.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-01/msg00017.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~6.8.8.1~30.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-debuginfo", rpm:"ImageMagick-debuginfo~6.8.8.1~30.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-debugsource", rpm:"ImageMagick-debugsource~6.8.8.1~30.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-devel", rpm:"ImageMagick-devel~6.8.8.1~30.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-extra", rpm:"ImageMagick-extra~6.8.8.1~30.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-extra-debuginfo", rpm:"ImageMagick-extra-debuginfo~6.8.8.1~30.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagick++-6_Q16-3", rpm:"libMagick++-6_Q16-3~6.8.8.1~30.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagick++-6_Q16-3-debuginfo", rpm:"libMagick++-6_Q16-3-debuginfo~6.8.8.1~30.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagick++-devel", rpm:"libMagick++-devel~6.8.8.1~30.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~30.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagickCore-6_Q16-1-debuginfo", rpm:"libMagickCore-6_Q16-1-debuginfo~6.8.8.1~30.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~30.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagickWand-6_Q16-1-debuginfo", rpm:"libMagickWand-6_Q16-1-debuginfo~6.8.8.1~30.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-PerlMagick", rpm:"perl-PerlMagick~6.8.8.1~30.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-PerlMagick-debuginfo", rpm:"perl-PerlMagick-debuginfo~6.8.8.1~30.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-doc", rpm:"ImageMagick-doc~6.8.8.1~30.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-devel-32bit", rpm:"ImageMagick-devel-32bit~6.8.8.1~30.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagick++-6_Q16-3-32bit", rpm:"libMagick++-6_Q16-3-32bit~6.8.8.1~30.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagick++-6_Q16-3-debuginfo-32bit", rpm:"libMagick++-6_Q16-3-debuginfo-32bit~6.8.8.1~30.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagick++-devel-32bit", rpm:"libMagick++-devel-32bit~6.8.8.1~30.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagickCore-6_Q16-1-32bit", rpm:"libMagickCore-6_Q16-1-32bit~6.8.8.1~30.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagickCore-6_Q16-1-debuginfo-32bit", rpm:"libMagickCore-6_Q16-1-debuginfo-32bit~6.8.8.1~30.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagickWand-6_Q16-1-32bit", rpm:"libMagickWand-6_Q16-1-32bit~6.8.8.1~30.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagickWand-6_Q16-1-debuginfo-32bit", rpm:"libMagickWand-6_Q16-1-debuginfo-32bit~6.8.8.1~30.15.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~6.8.8.1~43.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-debuginfo", rpm:"ImageMagick-debuginfo~6.8.8.1~43.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-debugsource", rpm:"ImageMagick-debugsource~6.8.8.1~43.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-devel", rpm:"ImageMagick-devel~6.8.8.1~43.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-extra", rpm:"ImageMagick-extra~6.8.8.1~43.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-extra-debuginfo", rpm:"ImageMagick-extra-debuginfo~6.8.8.1~43.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagick++-6_Q16-3", rpm:"libMagick++-6_Q16-3~6.8.8.1~43.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagick++-6_Q16-3-debuginfo", rpm:"libMagick++-6_Q16-3-debuginfo~6.8.8.1~43.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagick++-devel", rpm:"libMagick++-devel~6.8.8.1~43.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagickCore-6_Q16-1", rpm:"libMagickCore-6_Q16-1~6.8.8.1~43.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagickCore-6_Q16-1-debuginfo", rpm:"libMagickCore-6_Q16-1-debuginfo~6.8.8.1~43.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagickWand-6_Q16-1", rpm:"libMagickWand-6_Q16-1~6.8.8.1~43.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagickWand-6_Q16-1-debuginfo", rpm:"libMagickWand-6_Q16-1-debuginfo~6.8.8.1~43.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-PerlMagick", rpm:"perl-PerlMagick~6.8.8.1~43.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-PerlMagick-debuginfo", rpm:"perl-PerlMagick-debuginfo~6.8.8.1~43.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-doc", rpm:"ImageMagick-doc~6.8.8.1~43.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-devel-32bit", rpm:"ImageMagick-devel-32bit~6.8.8.1~43.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagick++-6_Q16-3-32bit", rpm:"libMagick++-6_Q16-3-32bit~6.8.8.1~43.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagick++-6_Q16-3-debuginfo-32bit", rpm:"libMagick++-6_Q16-3-debuginfo-32bit~6.8.8.1~43.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagick++-devel-32bit", rpm:"libMagick++-devel-32bit~6.8.8.1~43.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagickCore-6_Q16-1-32bit", rpm:"libMagickCore-6_Q16-1-32bit~6.8.8.1~43.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagickCore-6_Q16-1-debuginfo-32bit", rpm:"libMagickCore-6_Q16-1-debuginfo-32bit~6.8.8.1~43.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagickWand-6_Q16-1-32bit", rpm:"libMagickWand-6_Q16-1-32bit~6.8.8.1~43.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libMagickWand-6_Q16-1-debuginfo-32bit", rpm:"libMagickWand-6_Q16-1-debuginfo-32bit~6.8.8.1~43.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
