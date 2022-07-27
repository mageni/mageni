###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2019_0044_1.nasl 13489 2019-02-06 09:12:08Z cfischer $
#
# SuSE Update for haproxy openSUSE-SU-2019:0044-1 (haproxy)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852234");
  script_version("$Revision: 13489 $");
  script_cve_id("CVE-2018-20102", "CVE-2018-20103");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 10:12:08 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-12 04:02:32 +0100 (Sat, 12 Jan 2019)");
  script_name("SuSE Update for haproxy openSUSE-SU-2019:0044-1 (haproxy)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-01/msg00010.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'haproxy'
  package(s) announced via the openSUSE-SU-2019:0044_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for haproxy to version 1.8.15 fixes the following issues:

  Security issues fixed:

  - CVE-2018-20102: Fixed an out-of-bounds read in
  dns_validate_dns_response(), which allowed for memory disclosure
  (bsc#1119368)

  - CVE-2018-20103: Fixed an infinite recursion via crafted packet allows
  stack exhaustion and denial of service (bsc#1119419)

  Other notable bug fixes:

  - Fix off-by-one write in dns_validate_dns_response()

  - Fix out-of-bounds read via signedness error in
  dns_validate_dns_response()

  - Prevent out-of-bounds read in dns_validate_dns_response()

  - Prevent out-of-bounds read in dns_read_name()

  - Prevent stack-exhaustion via recursion loop in dns_read_name

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-44=1");

  script_tag(name:"affected", value:"haproxy on openSUSE Leap 15.0.");

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

  if ((res = isrpmvuln(pkg:"haproxy", rpm:"haproxy~1.8.15~git0.6b6a350a~lp150.2.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"haproxy-debuginfo", rpm:"haproxy-debuginfo~1.8.15~git0.6b6a350a~lp150.2.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"haproxy-debugsource", rpm:"haproxy-debugsource~1.8.15~git0.6b6a350a~lp150.2.6.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
