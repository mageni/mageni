###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for xen FEDORA-2015-12714
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
  script_oid("1.3.6.1.4.1.25623.1.0.869858");
  script_version("$Revision: 14223 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-08-13 06:37:06 +0200 (Thu, 13 Aug 2015)");
  script_cve_id("CVE-2015-5154", "CVE-2015-3259", "CVE-2015-3209", "CVE-2015-4163",
                "CVE-2015-4164", "CVE-2015-4103", "CVE-2015-4104", "CVE-2015-4105",
                "CVE-2015-4106", "CVE-2015-3456", "CVE-2015-3340", "CVE-2015-2752",
                "CVE-2015-2756", "CVE-2015-2751", "CVE-2015-2152", "CVE-2015-2151",
                "CVE-2015-1563", "CVE-2015-2044", "CVE-2015-2045", "CVE-2015-0361",
                "CVE-2014-9065", "CVE-2014-8866", "CVE-2014-8867", "CVE-2014-9030",
                "CVE-2014-8594", "CVE-2014-8595", "CVE-2014-0150");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for xen FEDORA-2015-12714");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"xen on Fedora 21");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-August/163681.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC21");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC21")
{

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~4.4.2~9.fc21", rls:"FC21")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
