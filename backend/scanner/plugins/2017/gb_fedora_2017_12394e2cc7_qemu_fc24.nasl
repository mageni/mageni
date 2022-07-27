###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for qemu FEDORA-2017-12394e2cc7
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.872304");
  script_version("$Revision: 14223 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-01-26 05:46:11 +0100 (Thu, 26 Jan 2017)");
  script_cve_id("CVE-2016-6836", "CVE-2016-7909", "CVE-2016-7994", "CVE-2016-8577",
		"CVE-2016-8578", "CVE-2016-8668", "CVE-2016-8669", "CVE-2016-8910",
		"CVE-2016-8909", "CVE-2016-9101", "CVE-2016-9103", "CVE-2016-9102",
		"CVE-2016-9104", "CVE-2016-9105", "CVE-2016-9106", "CVE-2016-9381",
		"CVE-2016-9921", "CVE-2016-9776", "CVE-2016-9845", "CVE-2016-9846",
		"CVE-2016-9907", "CVE-2016-9911", "CVE-2016-9913", "CVE-2016-10028",
		"CVE-2016-9908", "CVE-2016-9912", "CVE-2016-9922", "CVE-2016-9914",
		"CVE-2016-9915", "CVE-2016-9916");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for qemu FEDORA-2017-12394e2cc7");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"qemu on Fedora 24");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZR6TVHCSVY76P44HEPPSZLBWWKTNM4V7");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC24");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC24")
{

  if ((res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.6.2~6.fc24", rls:"FC24")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
