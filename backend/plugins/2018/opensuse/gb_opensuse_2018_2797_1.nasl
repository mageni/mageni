###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2797_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for hylafax+ openSUSE-SU-2018:2797-1 (hylafax+)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851901");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-09-22 07:44:07 +0200 (Sat, 22 Sep 2018)");
  script_cve_id("CVE-2018-17141");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for hylafax+ openSUSE-SU-2018:2797-1 (hylafax+)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'hylafax+'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for hylafax+ fixes the following issues:

  Security issues fixed in 5.6.1:

  - CVE-2018-17141: multiple vulnerabilities affecting fax page reception in
  JPEG format Specially crafted input may have allowed remote execution of
  arbitrary code (boo#1109084)

  Additionally, this update also contains all upstream corrections and
  bugfixes in the 5.6.1 version, including:

  - fix RFC2047 encoding by notify

  - add jobcontrol PageSize feature

  - don't wait forever after +FRH:3

  - fix faxmail transition between a message and external types

  - avoid pagehandling from introducing some unnecessary EOM signals

  - improve proxy connection error handling and logging

  - add initial ModemGroup limits feature

  - pass the user's uid onto the session log file for sent faxes

  - improve job waits to minimize triggers

  - add ProxyTaglineFormat and ProxyTSI features


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1027=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1027=1");
  script_tag(name:"affected", value:"hylafax+ on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-09/msg00044.html");
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

  if ((res = isrpmvuln(pkg:"hylafax+", rpm:"hylafax+~5.6.1~15.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hylafax+-client", rpm:"hylafax+-client~5.6.1~15.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hylafax+-client-debuginfo", rpm:"hylafax+-client-debuginfo~5.6.1~15.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hylafax+-debuginfo", rpm:"hylafax+-debuginfo~5.6.1~15.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hylafax+-debugsource", rpm:"hylafax+-debugsource~5.6.1~15.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfaxutil5_6_1", rpm:"libfaxutil5_6_1~5.6.1~15.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfaxutil5_6_1-debuginfo", rpm:"libfaxutil5_6_1-debuginfo~5.6.1~15.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
