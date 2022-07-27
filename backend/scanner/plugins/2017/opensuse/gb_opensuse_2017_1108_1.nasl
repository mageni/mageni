###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_1108_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for tiff openSUSE-SU-2017:1108-1 (tiff)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851541");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-04-27 07:17:10 +0200 (Thu, 27 Apr 2017)");
  script_cve_id("CVE-2016-10266", "CVE-2016-10267", "CVE-2016-10268", "CVE-2016-10269",
                "CVE-2016-10270", "CVE-2016-10271", "CVE-2016-10272");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for tiff openSUSE-SU-2017:1108-1 (tiff)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for tiff fixes the following issues:

  Security issues fixed:

  - CVE-2016-10272: LibTIFF 4.0.7 allows remote attackers to cause a denial
  of service (heap-based buffer overflow) or possibly have unspecified
  other impact via a crafted TIFF image, related to 'WRITE of size 2048'
  and libtiff/tif_next.c:64:9 (bsc#1031247).

  - CVE-2016-10271: tools/tiffcrop.c in LibTIFF 4.0.7 allows remote
  attackers to cause a denial of service (heap-based buffer over-read and
  buffer overflow) or possibly have unspecified other impact via a crafted
  TIFF image, related to 'READ of size 1' and libtiff/tif_fax3.c:413:13
  (bsc#1031249).

  - CVE-2016-10270: LibTIFF 4.0.7 allows remote attackers to cause a denial
  of service (heap-based buffer over-read) or possibly have unspecified
  other impact via a crafted TIFF image, related to 'READ of size 8' and
  libtiff/tif_read.c:523:22 (bsc#1031250).

  - CVE-2016-10269: LibTIFF 4.0.7 allows remote attackers to cause a denial
  of service (heap-based buffer over-read) or possibly have unspecified
  other impact via a crafted TIFF image, related to 'READ of size 512' and
  libtiff/tif_unix.c:340:2 (bsc#1031254).

  - CVE-2016-10268: tools/tiffcp.c in LibTIFF 4.0.7 allows remote attackers
  to cause a denial of service (integer underflow and heap-based buffer
  under-read) or possibly have unspecified other impact via a crafted TIFF
  image, related to 'READ of size 78490' and libtiff/tif_unix.c:115:23
  (bsc#1031255).

  - CVE-2016-10267: LibTIFF 4.0.7 allows remote attackers to cause a denial
  of service (divide-by-zero error and application crash) via a crafted
  TIFF image, related to libtiff/tif_ojpeg.c:816:8 (bsc#1031262).

  - CVE-2016-10266: LibTIFF 4.0.7 allows remote attackers to cause a denial
  of service (divide-by-zero error and application crash) via a crafted
  TIFF image, related to libtiff/tif_read.c:351:22. (bsc#1031263).

  This update was imported from the SUSE:SLE-12:Update update project.");
  script_tag(name:"affected", value:"tiff on openSUSE Leap 42.2, openSUSE Leap 42.1");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.2|openSUSELeap42\.1)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.2")
{

  if ((res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.0.7~17.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff5", rpm:"libtiff5~4.0.7~17.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff5-debuginfo", rpm:"libtiff5-debuginfo~4.0.7~17.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tiff", rpm:"tiff~4.0.7~17.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tiff-debuginfo", rpm:"tiff-debuginfo~4.0.7~17.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tiff-debugsource", rpm:"tiff-debugsource~4.0.7~17.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff-devel-32bit", rpm:"libtiff-devel-32bit~4.0.7~17.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff5-32bit", rpm:"libtiff5-32bit~4.0.7~17.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff5-debuginfo-32bit", rpm:"libtiff5-debuginfo-32bit~4.0.7~17.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSELeap42.1")
{

  if ((res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.0.7~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff5", rpm:"libtiff5~4.0.7~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff5-debuginfo", rpm:"libtiff5-debuginfo~4.0.7~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tiff", rpm:"tiff~4.0.7~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tiff-debuginfo", rpm:"tiff-debuginfo~4.0.7~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tiff-debugsource", rpm:"tiff-debugsource~4.0.7~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff-devel-32bit", rpm:"libtiff-devel-32bit~4.0.7~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff5-32bit", rpm:"libtiff5-32bit~4.0.7~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff5-debuginfo-32bit", rpm:"libtiff5-debuginfo-32bit~4.0.7~18.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
