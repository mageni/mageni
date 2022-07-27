###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_3370_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for tiff openSUSE-SU-2018:3370-1 (tiff)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852073");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2018-10779", "CVE-2018-16335", "CVE-2018-17100", "CVE-2018-17101", "CVE-2018-17795", "CVE-2017-9935", "CVE-2018-15209");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-26 06:41:45 +0200 (Fri, 26 Oct 2018)");
  script_name("SuSE Update for tiff openSUSE-SU-2018:3370-1 (tiff)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-10/msg00055.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff'
  package(s) announced via the openSUSE-SU-2018:3370_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tiff fixes the following issues:

  Security issue fixed:

  - CVE-2018-10779: TIFFWriteScanline in tif_write.c had a heap-based buffer
  over-read, as demonstrated by bmp2tiff.(bsc#1092480)

  - CVE-2018-17100: There is a int32 overflow in multiply_ms in
  tools/ppm2tiff.c, which can cause a denial of service (crash) or
  possibly have unspecified other impact via a crafted image file.
  (bsc#1108637)

  - CVE-2018-17101: There are two out-of-bounds writes in cpTags in
  tools/tiff2bw.c and tools/pal2rgb.c, which can cause a denial of service
  (application crash) or possibly have unspecified other impact via a
  crafted image file. (bsc#1108627)

  - CVE-2018-17795: The function t2p_write_pdf in tiff2pdf.c allowed remote
  attackers to cause a denial of service (heap-based buffer overflow and
  application crash) or possibly have unspecified other impact via a
  crafted TIFF file, a similar issue to CVE-2017-9935. (bsc#1110358)

  - CVE-2018-16335: newoffsets handling in ChopUpSingleUncompressedStrip in
  tif_dirread.c allowed remote attackers to cause a denial of service
  (heap-based buffer overflow and application crash) or possibly have
  unspecified other impact via a crafted TIFF file, as demonstrated by
  tiff2pdf. This is a different vulnerability than CVE-2018-15209.
  (bsc#1106853)


  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1242=1");

  script_tag(name:"affected", value:"tiff on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.0.9~lp150.4.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff5", rpm:"libtiff5~4.0.9~lp150.4.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff5-debuginfo", rpm:"libtiff5-debuginfo~4.0.9~lp150.4.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tiff", rpm:"tiff~4.0.9~lp150.4.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tiff-debuginfo", rpm:"tiff-debuginfo~4.0.9~lp150.4.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tiff-debugsource", rpm:"tiff-debugsource~4.0.9~lp150.4.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff-devel-32bit", rpm:"libtiff-devel-32bit~4.0.9~lp150.4.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff5-32bit", rpm:"libtiff5-32bit~4.0.9~lp150.4.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff5-32bit-debuginfo", rpm:"libtiff5-32bit-debuginfo~4.0.9~lp150.4.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
