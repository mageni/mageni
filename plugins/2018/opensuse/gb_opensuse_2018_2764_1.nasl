###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2764_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for exempi openSUSE-SU-2018:2764-1 (exempi)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851899");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-09-21 08:10:35 +0200 (Fri, 21 Sep 2018)");
  script_cve_id("CVE-2017-18233", "CVE-2017-18236", "CVE-2017-18238");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for exempi openSUSE-SU-2018:2764-1 (exempi)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'exempi'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for exempi fixes the following security issue:

  - CVE-2017-18236: The ASF_Support::ReadHeaderObject function allowed
  remote attackers to cause a denial of service (infinite loop) via a
  crafted .asf file (bsc#1085589)

  - CVE-2017-18233: Prevent integer overflow in the Chunk class that allowed
  remote attackers to cause a denial of service (infinite loop) via
  crafted XMP data in a .avi file (bsc#1085584)

  - CVE-2017-18238: The TradQT_Manager::ParseCachedBoxes function allowed
  remote attackers to cause a denial of service (infinite loop) via
  crafted XMP data in a .qt file (bsc#1085583)


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1022=1");
  script_tag(name:"affected", value:"exempi on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-09/msg00041.html");
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

  if ((res = isrpmvuln(pkg:"exempi-debugsource", rpm:"exempi-debugsource~2.2.2~6.8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"exempi-tools", rpm:"exempi-tools~2.2.2~6.8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"exempi-tools-debuginfo", rpm:"exempi-tools-debuginfo~2.2.2~6.8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libexempi-devel", rpm:"libexempi-devel~2.2.2~6.8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libexempi3", rpm:"libexempi3~2.2.2~6.8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libexempi3-debuginfo", rpm:"libexempi3-debuginfo~2.2.2~6.8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libexempi3-32bit", rpm:"libexempi3-32bit~2.2.2~6.8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libexempi3-debuginfo-32bit", rpm:"libexempi3-debuginfo-32bit~2.2.2~6.8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
