###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_0835_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for rubygem-actionpack-3_2 openSUSE-SU-2016:0835-1 (rubygem-actionpack-3_2)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851251");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-03-20 06:18:10 +0100 (Sun, 20 Mar 2016)");
  script_cve_id("CVE-2016-2097", "CVE-2016-2098");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for rubygem-actionpack-3_2 openSUSE-SU-2016:0835-1 (rubygem-actionpack-3_2)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem-actionpack-3_2'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for rubygem-actionpack-3_2 fixes the following issues:

  - CVE-2016-2097: rubygem-actionview: Possible Information Leak
  Vulnerability in Action View. (boo#968850)

  - CVE-2016-2098: rubygem-actionpack: Possible remote code execution
  vulnerability in Action Pack (boo#968849)");
  script_tag(name:"affected", value:"rubygem-actionpack-3_2 on openSUSE 13.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.2")
{

  if ((res = isrpmvuln(pkg:"rubygem-actionpack-3_2", rpm:"rubygem-actionpack-3_2~3.2.17~3.10.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-actionpack-3_2-doc", rpm:"rubygem-actionpack-3_2-doc~3.2.17~3.10.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
