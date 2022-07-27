###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_0570_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for freexl openSUSE-SU-2018:0570-1 (freexl)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851712");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-03-02 08:42:04 +0100 (Fri, 02 Mar 2018)");
  script_cve_id("CVE-2018-7435", "CVE-2018-7436", "CVE-2018-7437", "CVE-2018-7438",
                "CVE-2018-7439");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for freexl openSUSE-SU-2018:0570-1 (freexl)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'freexl'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for freexl fixes the following issues:

  freexl was updated to version 1.0.5:

  * No changelog provided by upstream

  * Various heapoverflows in 1.0.4 have been fixed:

  * CVE-2018-7439: heap-buffer-overflow in freexl.c:3912
  read_mini_biff_next_record (boo#1082774)

  * CVE-2018-7438: heap-buffer-overflow in freexl.c:383
  parse_unicode_string (boo#1082775)

  * CVE-2018-7437: heap-buffer-overflow in freexl.c:1866
  parse_SST(boo#1082776)

  * CVE-2018-7436: heap-buffer-overflow in freexl.c:1805 parse_SST
  parse_SST (boo#1082777)

  * CVE-2018-7435: heap-buffer-overflow in freexl::destroy_cell
  (boo#1082778)");
  script_tag(name:"affected", value:"freexl on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"freexl-debugsource", rpm:"freexl-debugsource~1.0.5~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freexl-devel", rpm:"freexl-devel~1.0.5~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreexl1", rpm:"libfreexl1~1.0.5~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreexl1-debuginfo", rpm:"libfreexl1-debuginfo~1.0.5~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
