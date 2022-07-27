###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for rpmdrake MDKA-2007:062 (rpmdrake)
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
tag_insight = "The rpmdrake package, which provides the graphical software
  installation and update tools rpmdrake, drakrpm-edit-media and
  MandrivaUpdate), included with Mandriva Linux 2007 Spring contains
  several bugs. These include:

  When installing software with rpmdrake, if packages are selected for
  installation which require other packages to be installed as well,
  a message will be displayed that says To satisfy dependencies,
  the following packages also need to be installed:, but no list of
  dependencies will actually be shown.
  
  When installing software with rpmdrake, searching for a package always
  searches through the full set of available packages even when a search
  filter - such as All updates or Mandriva choices - is selected.
  
  When installing software with rpmdrake, when you switch between two
  subsections with the same name - for instance, System/Settings/Other
  and Development/Other - the list of packages is not updated; in
  the example, the packages from the System/Settings/Other group
  will continue to be displayed, instead of the packages from
  Development/Other.
  
  Running rpmdrake with the --merge-all-rpmnew parameter, which uses
  rpmdrake to help you merge changes in updated configuration files,
  does not work.
  
  When updating your system with MandrivaUpdate, when a package name
  cannot be correctly parsed, the name of the previous package in the
  list will be displayed again instead.
  
  When installing software with rpmdrake, the application will crash
  if a package with a malformed summary in the Unicode text encoding
  system was selected.
  
  Some other, more minor bugs were also fixed in this update.";

tag_affected = "rpmdrake on Mandriva Linux 2007.1,
  Mandriva Linux 2007.1/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-06/msg00032.php");
  script_oid("1.3.6.1.4.1.25623.1.0.308973");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 13:48:43 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDKA", value: "2007:062");
  script_name( "Mandriva Update for rpmdrake MDKA-2007:062 (rpmdrake)");

  script_tag(name:"summary", value:"Check for the Version of rpmdrake");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
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

if(release == "MNDK_2007.1")
{

  if ((res = isrpmvuln(pkg:"park-rpmdrake", rpm:"park-rpmdrake~3.68~1.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rpmdrake", rpm:"rpmdrake~3.68~1.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
