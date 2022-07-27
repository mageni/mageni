###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_0497_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for p7zip openSUSE-SU-2018:0497-1 (p7zip)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851707");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-02-21 08:47:44 +0100 (Wed, 21 Feb 2018)");
  script_cve_id("CVE-2016-1372", "CVE-2017-17969", "CVE-2018-5996");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for p7zip openSUSE-SU-2018:0497-1 (p7zip)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'p7zip'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for p7zip fixes the following security issues:

  - CVE-2016-1372: Fixed multiple vulnerabilities when processing crafted 7z
  files (bsc#984650)

  - CVE-2017-17969: Fixed a heap-based buffer overflow in a shrink decoder
  (bsc#1077725)

  - CVE-2018-5996: Fixed memory corruption in RAR decompression. The
  complete RAR decoder was removed as it also has license issues
  (bsc#1077724 bsc#1077978)

  This update was imported from the SUSE:SLE-12:Update update project.");
  script_tag(name:"affected", value:"p7zip on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-02/msg00040.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"p7zip", rpm:"p7zip~9.20.1~18.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"p7zip-debuginfo", rpm:"p7zip-debuginfo~9.20.1~18.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"p7zip-debugsource", rpm:"p7zip-debugsource~9.20.1~18.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
