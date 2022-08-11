###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_0702_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for libXfont SUSE-SU-2015:0702-1 (libXfont)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850864");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-15 12:24:06 +0200 (Thu, 15 Oct 2015)");
  script_cve_id("CVE-2015-1802", "CVE-2015-1803", "CVE-2015-1804");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for libXfont SUSE-SU-2015:0702-1 (libXfont)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libXfont'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"LibXFont was updated to fix security problems.

  Following security issues were fixed:

  - CVE-2015-1802: The bdf parser reads a count for the number of properties
  defined in a font from the font file, and allocates arrays with entries
  for each property based on that count. It never checked to see if that
  count was negative, or large enough to overflow when multiplied by the
  size
  of the structures being allocated, and could thus allocate the wrong
  buffer size, leading to out of bounds writes.

  - CVE-2015-1803: If the bdf parser failed to parse the data for the bitmap
  for any character, it would proceed with an invalid pointer to the
  bitmap data and later crash when trying to read the bitmap from that
  pointer.

  - CVE-2015-1804: The bdf parser read metrics values as 32-bit integers,
  but stored them into 16-bit integers. Overflows could occur in various
  operations leading to out-of-bounds memory access.");
  script_tag(name:"affected", value:"libXfont on SUSE Linux Enterprise Desktop 12");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLED12\.0SP0");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLED12.0SP0")
{

  if ((res = isrpmvuln(pkg:"libXfont-debugsource", rpm:"libXfont-debugsource~1.4.7~4.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfont1", rpm:"libXfont1~1.4.7~4.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfont1-debuginfo", rpm:"libXfont1-debuginfo~1.4.7~4.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
