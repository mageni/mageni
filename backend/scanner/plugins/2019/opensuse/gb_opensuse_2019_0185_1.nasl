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
  script_oid("1.3.6.1.4.1.25623.1.0.852292");
  script_version("$Revision: 13867 $");
  script_cve_id("CVE-2018-14404", "CVE-2018-16468", "CVE-2018-16470");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 10:05:01 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-15 04:05:22 +0100 (Fri, 15 Feb 2019)");
  script_name("SuSE Update for rmt-server openSUSE-SU-2019:0185-1 (rmt-server)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-02/msg00026.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rmt-server'
  package(s) announced via the openSUSE-SU-2019:0185_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rmt-server to version 1.1.1 fixes
  the following issues:

  The following issues have been fixed:

  - Fixed migration problems which caused some extensions / modules to be
  dropped (bsc#1118584, bsc#1118579)

  - Fixed listing of mirrored products (bsc#1102193)

  - Include online migration paths into offline migration (bsc#1117106)

  - Sync products that do not have a base product (bsc#1109307)

  - Fixed SLP auto discovery for RMT (bsc#1113760)

  Update dependencies for security fixes:

  - CVE-2018-16468: Update loofah to 2.2.3 (bsc#1113969)

  - CVE-2018-16470: Update rack to 2.0.6 (bsc#1114831)

  - CVE-2018-14404: Update nokogiri to 1.8.5 (bsc#1102046)

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-185=1");

  script_tag(name:"affected", value:"rmt-server on openSUSE Leap 15.0.");

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

  if ((res = isrpmvuln(pkg:"rmt-server", rpm:"rmt-server~1.1.1~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rmt-server-debuginfo", rpm:"rmt-server-debuginfo~1.1.1~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mt-server-pubcloud", rpm:"mt-server-pubcloud~1.1.1~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
