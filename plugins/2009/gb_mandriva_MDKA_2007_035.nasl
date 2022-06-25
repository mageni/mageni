###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for curl MDKA-2007:035 (curl)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_affected = "curl on Mandriva Linux 2007.0,
  Mandriva Linux 2007.0/X86_64";
tag_insight = "The curl shipped with 2007.0 had a bug which prevented it from working
  with the Club repositories, meaning users could not access the Club
  repositories unless they switched the default downloader for urpmi and
  rpmdrake to be wget. This update fixes the bug and allows the Club
  repositories to work with curl as the default downloader for urpmi
  and rpmdrake, saving users the need to change the default downloader.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-05/msg00011.php");
  script_oid("1.3.6.1.4.1.25623.1.0.305139");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 13:48:43 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "MDKA", value: "2007:035");
  script_name( "Mandriva Update for curl MDKA-2007:035 (curl)");

  script_tag(name:"summary", value:"Check for the Version of curl");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
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

if(release == "MNDK_2007.0")
{

  if ((res = isrpmvuln(pkg:"curl", rpm:"curl~7.15.5~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl3", rpm:"libcurl3~7.15.5~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl3-devel", rpm:"libcurl3-devel~7.15.5~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64curl3", rpm:"lib64curl3~7.15.5~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64curl3-devel", rpm:"lib64curl3-devel~7.15.5~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
