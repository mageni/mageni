###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_2168_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for java-1_7_1-ibm SUSE-SU-2015:2168-1 (java-1_7_1-ibm)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851137");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-12-03 06:33:09 +0100 (Thu, 03 Dec 2015)");
  script_cve_id("CVE-2015-0204", "CVE-2015-0458", "CVE-2015-0459", "CVE-2015-0469",
                "CVE-2015-0477", "CVE-2015-0478", "CVE-2015-0480", "CVE-2015-0488",
                "CVE-2015-0491", "CVE-2015-4734", "CVE-2015-4803", "CVE-2015-4805",
                "CVE-2015-4806", "CVE-2015-4810", "CVE-2015-4835", "CVE-2015-4840",
                "CVE-2015-4842", "CVE-2015-4843", "CVE-2015-4844", "CVE-2015-4860",
                "CVE-2015-4871", "CVE-2015-4872", "CVE-2015-4882", "CVE-2015-4883",
                "CVE-2015-4893", "CVE-2015-4902", "CVE-2015-4903", "CVE-2015-4911",
                "CVE-2015-5006");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for java-1_7_1-ibm SUSE-SU-2015:2168-1 (java-1_7_1-ibm)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_1-ibm'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The java-1_7_1-ibm package was updated to versioin 7.1-3.20 to fix several
  security and non security issues:

  - bnc#955131: Version update to 7.1-3.20: CVE-2015-4734 CVE-2015-4803
  CVE-2015-4805 CVE-2015-4806 CVE-2015-4810 CVE-2015-4835 CVE-2015-4840
  CVE-2015-4842 CVE-2015-4843 CVE-2015-4844 CVE-2015-4860 CVE-2015-4871
  CVE-2015-4872 CVE-2015-4882 CVE-2015-4883 CVE-2015-4893 CVE-2015-4902
  CVE-2015-4903 CVE-2015-4911 CVE-2015-5006

  - Add backcompat symlinks for sdkdir

  - bnc#941939: Fix to provide %{name} instead of %{sdklnk} only in
  _jvmprivdir");
  script_tag(name:"affected", value:"java-1_7_1-ibm on SUSE Linux Enterprise Server 12");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES12\.0SP0");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLES12.0SP0")
{

  if ((res = isrpmvuln(pkg:"java-1_7_1-ibm", rpm:"java-1_7_1-ibm~1.7.1_sr3.20~17.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_1-ibm-jdbc", rpm:"java-1_7_1-ibm-jdbc~1.7.1_sr3.20~17.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_1-ibm-alsa", rpm:"java-1_7_1-ibm-alsa~1.7.1_sr3.20~17.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_1-ibm-plugin", rpm:"java-1_7_1-ibm-plugin~1.7.1_sr3.20~17.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
