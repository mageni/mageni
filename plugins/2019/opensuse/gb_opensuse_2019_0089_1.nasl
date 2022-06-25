###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2019_0089_1.nasl 13451 2019-02-05 05:56:56Z santu $
#
# SuSE Update for nodejs8 openSUSE-SU-2019:0089-1 (nodejs8)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.852258");
  script_version("$Revision: 13451 $");
  script_cve_id("CVE-2018-12116", "CVE-2018-12121", "CVE-2018-12122", "CVE-2018-12123");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 06:56:56 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-29 04:02:32 +0100 (Tue, 29 Jan 2019)");
  script_name("SuSE Update for nodejs8 openSUSE-SU-2019:0089-1 (nodejs8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-01/msg00039.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs8'
  package(s) announced via the openSUSE-SU-2019:0089_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs8 to version 8.15.0 fixes the following issues:

  Security issues fixed:

  - CVE-2018-12121: Fixed a Denial of Service with large HTTP headers
  (bsc#1117626)

  - CVE-2018-12122: Fixed the 'Slowloris' HTTP Denial of Service
  (bsc#1117627)

  - CVE-2018-12116: Fixed HTTP request splitting (bsc#1117630)

  - CVE-2018-12123: Fixed hostname spoofing in URL parser for javascript
  protocol (bsc#1117629)

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-89=1");

  script_tag(name:"affected", value:"nodejs8 on openSUSE Leap 15.0.");

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

  if ((res = isrpmvuln(pkg:"nodejs8", rpm:"nodejs8~8.15.0~lp150.2.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nodejs8-debuginfo", rpm:"nodejs8-debuginfo~8.15.0~lp150.2.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nodejs8-debugsource", rpm:"nodejs8-debugsource~8.15.0~lp150.2.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nodejs8-devel", rpm:"nodejs8-devel~8.15.0~lp150.2.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"npm8", rpm:"npm8~8.15.0~lp150.2.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nodejs8-docs", rpm:"nodejs8-docs~8.15.0~lp150.2.9.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
