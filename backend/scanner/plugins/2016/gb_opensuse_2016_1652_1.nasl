###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_1652_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for vlc openSUSE-SU-2016:1652-1 (vlc)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851353");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-23 05:24:34 +0200 (Thu, 23 Jun 2016)");
  script_cve_id("CVE-2015-7981", "CVE-2015-8126", "CVE-2016-1514", "CVE-2016-1515",
                "CVE-2016-5108");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for vlc openSUSE-SU-2016:1652-1 (vlc)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'vlc'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for vlc to 2.2.4 to fix the following security issue:

  - CVE-2016-5108: Fix out-of-bound write in adpcm QT IMA codec (boo#984382).

  This also include an update of codecs and libraries to fix these 3rd party
  security issues:

  - CVE-2016-1514: Matroska libebml EbmlUnicodeString Heap Information Leak

  - CVE-2016-1515: Matroska libebml Multiple ElementList Double Free
  Vulnerabilities

  - CVE-2015-7981: The png_convert_to_rfc1123 function in png.c in libpng
  allowed remote attackers to obtain sensitive process memory information
  via crafted tIME chunk data in an image file, which triggers an
  out-of-bounds read (bsc#952051).

  - CVE-2015-8126: Multiple buffer overflows in the (1) png_set_PLTE and (2)
  png_get_PLTE functions in libpng allowed remote attackers to cause a
  denial of service (application crash) or possibly have unspecified other
  impact via a small bit-depth value in an IHDR (aka image header) chunk
  in a PNG image (bsc#954980).");
  script_tag(name:"affected", value:"vlc on openSUSE Leap 42.1");
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

  if ((res = isrpmvuln(pkg:"libvlc5", rpm:"libvlc5~2.2.4~27.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvlc5-debuginfo", rpm:"libvlc5-debuginfo~2.2.4~27.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvlccore8", rpm:"libvlccore8~2.2.4~27.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvlccore8-debuginfo", rpm:"libvlccore8-debuginfo~2.2.4~27.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vlc", rpm:"vlc~2.2.4~27.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vlc-debuginfo", rpm:"vlc-debuginfo~2.2.4~27.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vlc-debugsource", rpm:"vlc-debugsource~2.2.4~27.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vlc-devel", rpm:"vlc-devel~2.2.4~27.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vlc-noX", rpm:"vlc-noX~2.2.4~27.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vlc-noX-debuginfo", rpm:"vlc-noX-debuginfo~2.2.4~27.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vlc-qt", rpm:"vlc-qt~2.2.4~27.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vlc-qt-debuginfo", rpm:"vlc-qt-debuginfo~2.2.4~27.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vlc-noX-lang", rpm:"vlc-noX-lang~2.2.4~27.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
