###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_3005_1.nasl 12523 2018-11-26 09:24:07Z mmartin $
#
# SuSE Update for otrs openSUSE-SU-2018:3005-1 (otrs)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852071");
  script_version("$Revision: 12523 $");
  script_cve_id("CVE-2018-14593", "CVE-2018-16586", "CVE-2018-16587");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-26 10:24:07 +0100 (Mon, 26 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-26 06:41:29 +0200 (Fri, 26 Oct 2018)");
  script_name("SuSE Update for otrs openSUSE-SU-2018:3005-1 (otrs)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-10/msg00005.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'otrs'
  package(s) announced via the openSUSE-SU-2018:3005_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for otrs to version 4.0.32 fixes the following issues:

  These security issues were fixed:

  - CVE-2018-16586: An attacker could have sent a malicious email to an OTRS
  system. If a logged in user opens it, the email could have caused the
  browser to load external image or CSS resources (bsc#1109822).

  - CVE-2018-16587: An attacker could have sent a malicious email to an OTRS
  system. If a user with admin permissions opens it, it caused deletions
  of arbitrary files that the OTRS web server user has write access to
  (bsc#1109823).

  - CVE-2018-14593: An attacker who is logged into OTRS as an agent may have
  escalated their privileges by accessing a specially crafted URL
  (bsc#1103800).

  These non-security issues were fixed:

  - fixed permissions file @OTRS_ROOT@/var/tmp -  @OTRS_ROOT@/var/tmp/

  - ACL for Action AgentTicketBulk were inconsistent.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1106=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2018-1106=1");

  script_tag(name:"affected", value:"otrs on openSUSE Leap 15.0.");

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

  if ((res = isrpmvuln(pkg:"otrs", rpm:"otrs~4.0.32~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"otrs-doc", rpm:"otrs-doc~4.0.32~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"otrs-itsm", rpm:"otrs-itsm~4.0.32~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
