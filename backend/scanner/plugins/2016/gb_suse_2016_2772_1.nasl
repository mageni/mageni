###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_2772_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for gd openSUSE-SU-2016:2772-1 (gd)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851431");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-11-11 05:47:37 +0100 (Fri, 11 Nov 2016)");
  script_cve_id("CVE-2016-6911", "CVE-2016-7568", "CVE-2016-8670");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for gd openSUSE-SU-2016:2772-1 (gd)");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for gd fixes the following security issues:

  - CVE-2016-7568: A specially crafted image file could cause an application
  crash or potentially execute arbitrary code when the image is converted
  to webp (bsc#1001900)

  - CVE-2016-8670: Stack Buffer Overflow in GD dynamicGetbuf (bsc#1004924)

  - CVE-2016-6911: Check for out-of-bound read in dynamicGetbuf()
  (bsc#1005274)

  This update was imported from the SUSE:SLE-12:Update update project.");
  script_tag(name:"affected", value:"gd on openSUSE Leap 42.1");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'gd'
  package(s) announced via the referenced advisory.");
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

  if ((res = isrpmvuln(pkg:"gd", rpm:"gd~2.1.0~13.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gd-debuginfo", rpm:"gd-debuginfo~2.1.0~13.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gd-debugsource", rpm:"gd-debugsource~2.1.0~13.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gd-devel", rpm:"gd-devel~2.1.0~13.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gd-32bit", rpm:"gd-32bit~2.1.0~13.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gd-debuginfo-32bit", rpm:"gd-debuginfo-32bit~2.1.0~13.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
