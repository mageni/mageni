###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_1956_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for tiff openSUSE-SU-2018:1956-1 (tiff)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851955");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2017-11613", "CVE-2017-18013", "CVE-2018-10963", "CVE-2018-7456", "CVE-2018-8905");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-26 06:22:31 +0200 (Fri, 26 Oct 2018)");
  script_name("SuSE Update for tiff openSUSE-SU-2018:1956-1 (tiff)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-07/msg00017.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff'
  package(s) announced via the openSUSE-SU-2018:1956_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tiff fixes the following security issues:

  These security issues were fixed:

  - CVE-2017-18013: Fixed a NULL pointer dereference in the
  tif_print.cTIFFPrintDirectory function that could have lead to denial of
  service (bsc#1074317).

  - CVE-2018-10963: Fixed an assertion failure in the
  TIFFWriteDirectorySec() function in tif_dirwrite.c, which allowed remote
  attackers to cause a denial
  of service via a crafted file (bsc#1092949).

  - CVE-2018-7456: Prevent a NULL Pointer dereference in the function
  TIFFPrintDirectory when using the tiffinfo tool to print crafted TIFF
  information, a different vulnerability than CVE-2017-18013 (bsc#1082825).

  - CVE-2017-11613: Prevent denial of service in the TIFFOpen function.
  During the TIFFOpen process, td_imagelength is not checked. The value of
  td_imagelength can be directly controlled by an input file. In the
  ChopUpSingleUncompressedStrip function, the _TIFFCheckMalloc function is
  called based on td_imagelength. If the value of td_imagelength is set
  close to the amount of system memory, it will hang the system or trigger
  the OOM killer (bsc#1082332).

  - CVE-2018-8905: Prevent heap-based buffer overflow in the function
  LZWDecodeCompat via a crafted TIFF file (bsc#1086408).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-728=1");

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

  if ((res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.0.9~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff5", rpm:"libtiff5~4.0.9~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff5-debuginfo", rpm:"libtiff5-debuginfo~4.0.9~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tiff", rpm:"tiff~4.0.9~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tiff-debuginfo", rpm:"tiff-debuginfo~4.0.9~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tiff-debugsource", rpm:"tiff-debugsource~4.0.9~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff-devel-32bit", rpm:"libtiff-devel-32bit~4.0.9~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff5-32bit", rpm:"libtiff5-32bit~4.0.9~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff5-32bit-debuginfo", rpm:"libtiff5-32bit-debuginfo~4.0.9~lp150.4.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
