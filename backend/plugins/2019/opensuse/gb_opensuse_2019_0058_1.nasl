###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2019_0058_1.nasl 13595 2019-02-12 08:06:21Z mmartin $
#
# SuSE Update for live555 openSUSE-SU-2019:0058-1 (live555)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852244");
  script_version("$Revision: 13595 $");
  script_cve_id("CVE-2018-4013", "CVE-2019-6256");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 09:06:21 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-18 04:03:17 +0100 (Fri, 18 Jan 2019)");
  script_name("SuSE Update for live555 openSUSE-SU-2019:0058-1 (live555)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.3|openSUSELeap15\.0)");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-01/msg00026.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'live555'
  package(s) announced via the openSUSE-SU-2019:0058_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes two security issues in live555:

  - CVE-2018-4013: Remote code execution vulnerability (bsc#1114779)

  - CVE-2019-6256: Denial of Service issue with RTSP-over-HTTP tunneling via
  x-sessioncookie HTTP headers (boo#1121892)

  This library is statically linked into VLC. However VLC is not affected
  because it only uses the live555 library to implement the RTSP client.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-58=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-58=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2019-58=1");

  script_tag(name:"affected", value:"live555 on openSUSE Leap 42.3, openSUSE Leap 15.0.");

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

  if ((res = isrpmvuln(pkg:"live555-devel", rpm:"live555-devel~2018.12.14~7.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"live555-devel", rpm:"live555-devel~2018.12.14~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
