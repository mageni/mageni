# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852311");
  script_version("$Revision: 13949 $");
  script_cve_id("CVE-2018-0734", "CVE-2018-12116", "CVE-2018-12120", "CVE-2018-12121", "CVE-2018-12122", "CVE-2018-12123", "CVE-2018-5407");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 08:26:12 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-02-23 04:07:21 +0100 (Sat, 23 Feb 2019)");
  script_name("SuSE Update for nodejs6 openSUSE-SU-2019:0234-1 (nodejs6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-02/msg00052.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs6'
  package(s) announced via the openSUSE-SU-2019:0234_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs6 to version 6.16.0 fixes the following issues:

  Security issues fixed:

  - CVE-2018-0734: Fixed a timing vulnerability in the DSA signature
  generation (bsc#1113652)

  - CVE-2018-5407: Fixed a hyperthread port content side channel attack (aka
  'PortSmash') (bsc#1113534)

  - CVE-2018-12120: Fixed that the debugger listens on any interface by
  default (bsc#1117625)

  - CVE-2018-12121: Fixed a denial of Service with large HTTP headers
  (bsc#1117626)

  - CVE-2018-12122: Fixed the 'Slowloris' HTTP Denial of Service
  (bsc#1117627)

  - CVE-2018-12116: Fixed HTTP request splitting (bsc#1117630)

  - CVE-2018-12123: Fixed hostname spoofing in URL parser for javascript
  protocol (bsc#1117629)

  This update was imported from the SUSE:SLE-12:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-234=1");

  script_tag(name:"affected", value:"nodejs6 on openSUSE Leap 42.3.");

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

  if ((res = isrpmvuln(pkg:"nodejs6", rpm:"nodejs6~6.16.0~18.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nodejs6-debuginfo", rpm:"nodejs6-debuginfo~6.16.0~18.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nodejs6-debugsource", rpm:"nodejs6-debugsource~6.16.0~18.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nodejs6-devel", rpm:"nodejs6-devel~6.16.0~18.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"npm6", rpm:"npm6~6.16.0~18.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nodejs6-docs", rpm:"nodejs6-docs~6.16.0~18.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
