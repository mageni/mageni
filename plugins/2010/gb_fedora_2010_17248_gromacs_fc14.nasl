###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for gromacs FEDORA-2010-17248
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "GROMACS is a versatile and extremely well optimized package to perform
  molecular dynamics computer simulations and subsequent trajectory analysis.
  It is developed for biomolecules like proteins, but the extremely high
  performance means it is used also in several other field like polymer chemistry
  and solid state physics.

  This package provides single and double precision binaries.
  The documentation is in the package gromacs-common.
  
  mdrun has been compiled with thread parallellization, so it runs in parallel
  on shared memory systems. If you want to run on a cluster, you probably want
  to install one of the MPI parallellized packages.
  
  N.B. All binaries have names starting with g_, for example mdrun has been
  renamed to g_mdrun.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "gromacs on Fedora 14";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-November/050763.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314459");
  script_version("$Revision: 8287 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-04 08:28:11 +0100 (Thu, 04 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-12-02 08:39:14 +0100 (Thu, 02 Dec 2010)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "FEDORA", value: "2010-17248");
  script_cve_id("CVE-2010-4001");
  script_name("Fedora Update for gromacs FEDORA-2010-17248");

  script_tag(name: "summary" , value: "Check for the Version of gromacs");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC14")
{

  if ((res = isrpmvuln(pkg:"gromacs", rpm:"gromacs~4.5.2~2.fc14", rls:"FC14")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
