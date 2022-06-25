###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_4124_1.nasl 12954 2019-01-07 07:56:42Z cfischer $
#
# SuSE Update for phpMyAdmin openSUSE-SU-2018:4124-1 (phpMyAdmin)
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
  script_oid("1.3.6.1.4.1.25623.1.0.814560");
  script_version("$Revision: 12954 $");
  script_cve_id("CVE-2018-19968", "CVE-2018-19969", "CVE-2018-19970");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-01-07 08:56:42 +0100 (Mon, 07 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-12-18 07:40:27 +0100 (Tue, 18 Dec 2018)");
  script_name("SuSE Update for phpMyAdmin openSUSE-SU-2018:4124-1 (phpMyAdmin)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.3|openSUSELeap15\.0)");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-12/msg00032.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpMyAdmin'
  package(s) announced via the openSUSE-SU-2018:4124_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for phpMyAdmin fixes security issues and bugs.

  Security issues addressed in the 4.8.4 release (bsc#1119245):

  - CVE-2018-19968: Local file inclusion through transformation feature

  - CVE-2018-19969: XSRF/CSRF vulnerability

  - CVE-2018-19970: XSS vulnerability in navigation tree

  This update also contains the following upstream bug fixes and
  improvements:

  - Ensure that database names with a dot ('.') are handled properly when
  DisableIS is true

  - Fix for message 'Error while copying database (pma__column_info)'

  - Move operation causes 'SELECT * FROM `undefined`' error

  - When logging with $cfg['AuthLog'] to syslog, successful login messages
  were not logged when $cfg['AuthLogSuccess'] was true

  - Multiple errors and regressions with Designer


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1547=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1547=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2018-1547=1");

  script_tag(name:"affected", value:"phpMyAdmin on openSUSE Leap 42.3, openSUSE Leap 15.0.");

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

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"phpMyAdmin", rpm:"phpMyAdmin~4.8.4~24.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"phpMyAdmin", rpm:"phpMyAdmin~4.8.4~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
