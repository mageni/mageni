###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_3258_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for icinga openSUSE-SU-2018:3258-1 (icinga)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851944");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-20 07:33:47 +0200 (Sat, 20 Oct 2018)");
  script_cve_id("CVE-2015-8010", "CVE-2016-0726", "CVE-2016-10089", "CVE-2016-8641");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for icinga openSUSE-SU-2018:3258-1 (icinga)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'icinga'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for icinga fixes the following issues:

  Update to 1.14.0

  - CVE-2015-8010: Fixed XSS in the icinga classic UI (boo#952777)

  - CVE-2016-8641 / CVE-2016-10089: fixed a possible symlink attack for
  files/dirs created by root (boo#1011630 and boo#1018047)

  - CVE-2016-0726: removed the pre-configured administrative account with
  fixed password for the WebUI - (boo#961115)


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1206=1");
  script_tag(name:"affected", value:"icinga on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-10/msg00043.html");
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

  if ((res = isrpmvuln(pkg:"icinga", rpm:"icinga~1.14.0~8.3.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icinga-debuginfo", rpm:"icinga-debuginfo~1.14.0~8.3.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icinga-debugsource", rpm:"icinga-debugsource~1.14.0~8.3.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icinga-devel", rpm:"icinga-devel~1.14.0~8.3.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icinga-doc", rpm:"icinga-doc~1.14.0~8.3.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icinga-idoutils", rpm:"icinga-idoutils~1.14.0~8.3.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icinga-idoutils-debuginfo", rpm:"icinga-idoutils-debuginfo~1.14.0~8.3.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icinga-idoutils-mysql", rpm:"icinga-idoutils-mysql~1.14.0~8.3.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icinga-idoutils-oracle", rpm:"icinga-idoutils-oracle~1.14.0~8.3.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icinga-idoutils-pgsql", rpm:"icinga-idoutils-pgsql~1.14.0~8.3.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icinga-plugins-downtimes", rpm:"icinga-plugins-downtimes~1.14.0~8.3.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icinga-plugins-eventhandlers", rpm:"icinga-plugins-eventhandlers~1.14.0~8.3.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icinga-www", rpm:"icinga-www~1.14.0~8.3.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icinga-www-config", rpm:"icinga-www-config~1.14.0~8.3.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icinga-www-debuginfo", rpm:"icinga-www-debuginfo~1.14.0~8.3.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"monitoring-tools", rpm:"monitoring-tools~1.14.0~8.3.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"monitoring-tools-debuginfo", rpm:"monitoring-tools-debuginfo~1.14.0~8.3.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
