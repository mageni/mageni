###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_3818_1.nasl 12799 2018-12-14 07:38:54Z ckuersteiner $
#
# SuSE Update for squid openSUSE-SU-2018:3818-1 (squid)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852139");
  script_version("$Revision: 12799 $");
  script_cve_id("CVE-2018-19131", "CVE-2018-19132");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-14 08:38:54 +0100 (Fri, 14 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-11-21 06:03:56 +0100 (Wed, 21 Nov 2018)");
  script_name("SuSE Update for squid openSUSE-SU-2018:3818-1 (squid)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-11/msg00029.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid'
  package(s) announced via the openSUSE-SU-2018:3818_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for squid fixes the following issues:

  Security issues fixed:

  - CVE-2018-19131: Fixed Cross-Site-Scripting vulnerability in the TLS
  error handling (bsc#1113668).

  - CVE-2018-19132: Fixed small memory leak in processing of SNMP packets
  (bsc#1113669).

  Non-security issues fixed:

  - Create runtime directories needed when SMP mode is enabled (bsc#1112695,
  bsc#1112066).

  - Install license correctly (bsc#1082318).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1429=1");

  script_tag(name:"affected", value:"squid on openSUSE Leap 15.0.");

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

  if ((res = isrpmvuln(pkg:"squid", rpm:"squid~4.4~lp150.4.3.2", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squid-debuginfo", rpm:"squid-debuginfo~4.4~lp150.4.3.2", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squid-debugsource", rpm:"squid-debugsource~4.4~lp150.4.3.2", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
