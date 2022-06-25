###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_0847_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for novell-qtgui, SUSE-SU-2014:0847-1 (novell-qtgui,)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850856");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-15 12:20:18 +0200 (Thu, 15 Oct 2015)");
  script_cve_id("CVE-2014-0595");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for novell-qtgui, SUSE-SU-2014:0847-1 (novell-qtgui, )");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'novell-qtgui.'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Packages novell-ui-base and novell-qtgui were updated to prevent erroneous
  rights assignment when a user is granted 'File Scan' rights (F). In this
  case nwrights was assigning Supervisor (S) rights. (CVE-2014-0595)");

  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=872796");

  script_tag(name:"affected", value:"novell-qtgui, on SUSE Linux Enterprise Desktop 11 SP3");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLED11\.0SP3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLED11.0SP3")
{

  if ((res = isrpmvuln(pkg:"novell-qtgui", rpm:"novell-qtgui~3.0.0~0.20.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"novell-qtgui-cli", rpm:"novell-qtgui-cli~3.0.0~0.20.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"novell-ui-base", rpm:"novell-ui-base~3.0.0~0.10.1", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
