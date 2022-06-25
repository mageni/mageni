###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_0207_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for openjpeg2 openSUSE-SU-2017:0207-1 (openjpeg2)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851480");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-01-20 05:40:23 +0100 (Fri, 20 Jan 2017)");
  script_cve_id("CVE-2016-7445", "CVE-2016-8332", "CVE-2016-9112", "CVE-2016-9113",
                "CVE-2016-9114", "CVE-2016-9115", "CVE-2016-9116", "CVE-2016-9117",
                "CVE-2016-9118", "CVE-2016-9572", "CVE-2016-9573", "CVE-2016-9580",
                "CVE-2016-9581");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for openjpeg2 openSUSE-SU-2017:0207-1 (openjpeg2)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjpeg2'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for openjpeg2 fixes the following issues:

  * CVE-2016-9572 CVE-2016-9573: Insuficient check in imagetopnm() could
  lead to heap buffer overflow [bsc#1014543]

  * CVE-2016-9580, CVE-2016-9581: Possible Heap buffer overflow via integer
  overflow and infite loop [bsc#1014975]

  * CVE-2016-7445: Null pointer dereference in convert.c could lead to crash
  [bsc#999817]

  * CVE-2016-8332: Malicious file in OpenJPEG JPEG2000 format  could lead to
  code execution [bsc#1002414]

  * CVE-2016-9112: FPE(Floating Point Exception) in lib/openjp2/pi.c:523
  [bsc#1007747]

  * CVE-2016-9113: NULL point dereference in function imagetobmp of
  convertbmp.c could lead to crash [bsc#1007739]

  * CVE-2016-9114: NULL Pointer Access in function imagetopnm of
  convert.c:1943(jp2) could lead to crash [bsc#1007740]

  * CVE-2016-9115: Heap Buffer Overflow in function imagetotga of
  convert.c(jp2) [bsc#1007741]

  * CVE-2016-9116: NULL Pointer Access in function imagetopnm of
  convert.c:2226(jp2) [bsc#1007742]

  * CVE-2016-9117: NULL Pointer Access in function imagetopnm of
  convert.c(jp2):1289 [bsc#1007743]

  * CVE-2016-9118: Heap Buffer Overflow in function pnmtoimage of convert.c
  [bsc#1007744]");
  script_tag(name:"affected", value:"openjpeg2 on openSUSE Leap 42.1");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"libopenjp2-7", rpm:"libopenjp2-7~2.1.0~9.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenjp2-7-debuginfo", rpm:"libopenjp2-7-debuginfo~2.1.0~9.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openjpeg2", rpm:"openjpeg2~2.1.0~9.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openjpeg2-debuginfo", rpm:"openjpeg2-debuginfo~2.1.0~9.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openjpeg2-debugsource", rpm:"openjpeg2-debugsource~2.1.0~9.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openjpeg2-devel", rpm:"openjpeg2-devel~2.1.0~9.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenjp2-7-32bit", rpm:"libopenjp2-7-32bit~2.1.0~9.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenjp2-7-debuginfo-32bit", rpm:"libopenjp2-7-debuginfo-32bit~2.1.0~9.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
