###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_0521_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for obs-service-download_files, openSUSE-SU-2016:0521-1 (obs-service-download_files,)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851211");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-03-01 11:08:51 +0530 (Tue, 01 Mar 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_cve_id("CVE-2016-4007");
  script_name("SuSE Update for obs-service-download_files, openSUSE-SU-2016:0521-1 (obs-service-download_files, )");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'obs-service-download_files.'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for a number of source services fixes the following issues:

  - boo#967265: Various code/parameter injection issues could have allowed
  malicious service definition to execute commands or make changes to the
  user's file system

  The following source services are affected

  - obs-service-source_validator

  - obs-service-extract_file

  - obs-service-download_files

  - obs-service-recompress

  - obs-service-verify_file

  Also contains all bug fixes and improvements from the openSUSE:Tools
  versions.");
  script_tag(name:"affected", value:"obs-service-download_files, on openSUSE 13.2");
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

  if ((res = isrpmvuln(pkg:"obs-service-download_files", rpm:"obs-service-download_files~0.5.1.git.1455712026.9c0a4a0~2.6.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"obs-service-extract_file", rpm:"obs-service-extract_file~0.3~3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"obs-service-recompress", rpm:"obs-service-recompress~0.3.1+git20160217.7897d3f~3.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"obs-service-source_validator", rpm:"obs-service-source_validator~0.6+git20160218.73d6618~3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"obs-service-verify_file", rpm:"obs-service-verify_file~0.1.1~12.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
