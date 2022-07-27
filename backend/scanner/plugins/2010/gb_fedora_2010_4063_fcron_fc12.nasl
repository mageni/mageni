###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for fcron FEDORA-2010-4063
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
tag_insight = "Fcron is a scheduler. It aims at replacing Vixie Cron, so it implements most
  of its functionalities.
  But contrary to Vixie Cron, fcron does not need your system to be up 7 days
  a week, 24 hours a day: it also works well with systems which are
  not running neither all the time nor regularly (contrary to anacrontab).
  In other words, fcron does both the job of Vixie Cron and anacron, but does
  even more and better :)) ...

  WARNING: fcron isn't started automatically on boot after installation.
  You can use system-config-services to enable automatic fcron startup
  on boot, or use chkconfig as explained in the
  /usr/share/doc/fcron-3.0.5/README.Package file.";

tag_affected = "fcron on Fedora 12";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-March/038150.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313946");
  script_version("$Revision: 8314 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-08 09:01:01 +0100 (Mon, 08 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-03-31 14:20:46 +0200 (Wed, 31 Mar 2010)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_xref(name: "FEDORA", value: "2010-4063");
  script_cve_id("CVE-2010-0792");
  script_name("Fedora Update for fcron FEDORA-2010-4063");

  script_tag(name: "summary" , value: "Check for the Version of fcron");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
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

if(release == "FC12")
{

  if ((res = isrpmvuln(pkg:"fcron", rpm:"fcron~3.0.5~1.fc12", rls:"FC12")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
