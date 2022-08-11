###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_4174_1.nasl 13338 2019-01-29 07:44:39Z mmartin $
#
# SuSE Update for salt openSUSE-SU-2018:4174-1 (salt)
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
  script_oid("1.3.6.1.4.1.25623.1.0.814576");
  script_version("$Revision: 13338 $");
  script_cve_id("CVE-2018-15750", "CVE-2018-15751");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-01-29 08:44:39 +0100 (Tue, 29 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-12-19 10:09:00 +0100 (Wed, 19 Dec 2018)");
  script_name("SuSE Update for salt openSUSE-SU-2018:4174-1 (salt)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-12/msg00048.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'salt'
  package(s) announced via the openSUSE-SU-2018:4174_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for salt fixes the following issues:

  Security issues fixed:

  - CVE-2018-15750: Fixed directory traversal vulnerability in salt-api
  (bsc#1113698).

  - CVE-2018-15751: Fixed remote authentication bypass in salt-api(netapi)
  that allows to execute arbitrary commands (bsc#1113699).

  Non-security issues fixed:

  - Improved handling of LDAP group id. gid is no longer treated as a
  string, which could have lead to faulty group creations (bsc#1113784).

  - Fixed async call to process manager (bsc#1110938)

  - Fixed OS arch detection when RPM is not installed (bsc#1114197)

  - Crontab module fix: file attributes option missing (bsc#1114824)

  - Fix git_pillar merging across multiple __env__ repositories (bsc#1112874)

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1569=1");

  script_tag(name:"affected", value:"salt on openSUSE Leap 15.0.");

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

  if ((res = isrpmvuln(pkg:"python2-salt", rpm:"python2-salt~2018.3.0~lp150.3.17.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python3-salt", rpm:"python3-salt~2018.3.0~lp150.3.17.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"salt", rpm:"salt~2018.3.0~lp150.3.17.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"salt-api", rpm:"salt-api~2018.3.0~lp150.3.17.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"salt-cloud", rpm:"salt-cloud~2018.3.0~lp150.3.17.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~2018.3.0~lp150.3.17.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"salt-master", rpm:"salt-master~2018.3.0~lp150.3.17.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~2018.3.0~lp150.3.17.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"salt-proxy", rpm:"salt-proxy~2018.3.0~lp150.3.17.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"salt-ssh", rpm:"salt-ssh~2018.3.0~lp150.3.17.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"salt-syndic", rpm:"salt-syndic~2018.3.0~lp150.3.17.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"salt-bash-completion", rpm:"salt-bash-completion~2018.3.0~lp150.3.17.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"salt-fish-completion", rpm:"salt-fish-completion~2018.3.0~lp150.3.17.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"salt-zsh-completion", rpm:"salt-zsh-completion~2018.3.0~lp150.3.17.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
