###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_3951_1.nasl 12806 2018-12-17 06:39:00Z ckuersteiner $
#
# SuSE Update for rubygem-loofah openSUSE-SU-2018:3951-1 (rubygem-loofah)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852152");
  script_version("$Revision: 12806 $");
  script_cve_id("CVE-2018-16468");
  script_bugtraq_id(106054);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-17 07:39:00 +0100 (Mon, 17 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-04 12:40:38 +0530 (Tue, 04 Dec 2018)");
  script_name("SuSE Update for rubygem-loofah openSUSE-SU-2018:3951-1 (rubygem-loofah)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-11/msg00051.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem-loofah'
  package(s) announced via the openSUSE-SU-2018:3951_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rubygem-loofah fixes the following issues:

  Security issue fixed:

  - CVE-2018-16468: Fixed XXS by removing the svg animate attribute `from`
  from the allowlist (bsc#1113969).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1478=1");

  script_tag(name:"affected", value:"rubygem-loofah on openSUSE Leap 15.0.");

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

  if ((res = isrpmvuln(pkg:"ruby2.5-rubygem-loofah", rpm:"ruby2.5-rubygem-loofah~2.2.2~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby2.5-rubygem-loofah-doc", rpm:"ruby2.5-rubygem-loofah-doc~2.2.2~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"uby2.5-rubygem-loofah-testsuite", rpm:"uby2.5-rubygem-loofah-testsuite~2.2.2~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}