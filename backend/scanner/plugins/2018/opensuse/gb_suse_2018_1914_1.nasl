###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_1914_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for unzip openSUSE-SU-2018:1914-1 (unzip)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851967");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2014-9636", "CVE-2018-1000035");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-26 06:23:46 +0200 (Fri, 26 Oct 2018)");
  script_name("SuSE Update for unzip openSUSE-SU-2018:1914-1 (unzip)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-07/msg00013.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unzip'
  package(s) announced via the openSUSE-SU-2018:1914_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for unzip fixes the following issues:

  - CVE-2014-9636: Prevent denial of service (out-of-bounds read or write
  and crash) via an extra field with an uncompressed size smaller than the
  compressed field size in a zip archive that advertises STORED method
  compression (bsc#914442)

  - CVE-2018-1000035: Prevent heap-based buffer overflow in the processing
  of password-protected archives that allowed an attacker to perform a
  denial of service or to possibly achieve code execution (bsc#1080074)

  This non-security issue was fixed:

  +- Allow processing of Windows zip64 archives (Windows archivers set
  total_disks field to 0 but per standard, valid values are 1 and higher)
  (bnc#910683)

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-709=1");

  script_tag(name:"affected", value:"unzip on openSUSE Leap 15.0.");

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

  if ((res = isrpmvuln(pkg:"unzip", rpm:"unzip~6.00~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"unzip-debuginfo", rpm:"unzip-debuginfo~6.00~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"unzip-debugsource", rpm:"unzip-debugsource~6.00~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"unzip-doc", rpm:"unzip-doc~6.00~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"unzip-rcc", rpm:"unzip-rcc~6.00~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"unzip-rcc-debuginfo", rpm:"unzip-rcc-debuginfo~6.00~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"unzip-rcc-debugsource", rpm:"unzip-rcc-debugsource~6.00~lp150.3.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
