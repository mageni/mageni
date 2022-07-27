###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2019_0054_1.nasl 13750 2019-02-19 07:33:36Z mmartin $
#
# SuSE Update for gitolite openSUSE-SU-2019:0054-1 (gitolite)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852241");
  script_version("$Revision: 13750 $");
  script_cve_id("CVE-2018-20683");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-19 08:33:36 +0100 (Tue, 19 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-18 04:02:46 +0100 (Fri, 18 Jan 2019)");
  script_name("SuSE Update for gitolite openSUSE-SU-2019:0054-1 (gitolite)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.3|openSUSELeap15\.0)");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-01/msg00024.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gitolite'
  package(s) announced via the openSUSE-SU-2019:0054_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gitolite fixes the following security issue:

  - CVE-2018-20683: The rsync command line was not handled correctly, allow
  malicious rsync options (boo#1121570)

  The version update to 3.6.11 also contains a number of upstream bug fixes.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-54=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-54=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2019-54=1");

  script_tag(name:"affected", value:"gitolite on openSUSE Leap 42.3, openSUSE Leap 15.0.");

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

  if ((res = isrpmvuln(pkg:"gitolite", rpm:"gitolite~3.6.11~4.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"gitolite", rpm:"gitolite~3.6.11~lp150.2.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
