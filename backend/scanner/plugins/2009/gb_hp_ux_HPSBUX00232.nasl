###############################################################################
# OpenVAS Vulnerability Test
#
# HP-UX Update for xntpd HPSBUX00232
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
tag_impact = "Remote denial of service (DoS)";
tag_affected = "xntpd on
  HP-UX B.10.20, B.10.24, B.11.00, B.11.04, and B.11.11 using the xntpd 
  software.";
tag_insight = "A vulnerability in HP-UX running xntpd which may allow aremote user to 
  create a denial of service (DoS).";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c01035763-2");
  script_oid("1.3.6.1.4.1.25623.1.0.306290");
  script_version("$Revision: 6584 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 16:13:23 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-05-05 12:14:23 +0200 (Tue, 05 May 2009)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_xref(name: "HPSBUX", value: "00232");
  script_name( "HP-UX Update for xntpd HPSBUX00232");

  script_tag(name:"summary", value:"Check for the Version of xntpd");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("HP-UX Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/hp_hp-ux", "ssh/login/release");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-hpux.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "HPUX11.00")
{

  if ((res = ishpuxpkgvuln(pkg:"InternetSrvcs.INETSVCS-BOOT", patch_list:['PHNE_27223'], rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"InternetSrvcs.INET-ENG-A-MAN", patch_list:['PHNE_27223'], rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX10.24")
{

  if ((res = ishpuxpkgvuln(pkg:"InternetSrvcs.INETSVCS-BOOT", patch_list:['PHNE_28002'], rls:"HPUX10.24")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"InternetSrvcs.INET-ENG-A-MAN", patch_list:['PHNE_28002'], rls:"HPUX10.24")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.04")
{

  if ((res = ishpuxpkgvuln(pkg:"InternetSrvcs.INETSVCS-BOOT", patch_list:['PHNE_27442'], rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"InternetSrvcs.INET-ENG-A-MAN", patch_list:['PHNE_27442'], rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX10.20")
{

  if ((res = ishpuxpkgvuln(pkg:"InternetSrvcs.INETSVCS-BOOT", patch_list:['PHNE_24510'], rls:"HPUX10.20")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"InternetSrvcs.INET-ENG-A-MAN", patch_list:['PHNE_24510'], rls:"HPUX10.20")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.11")
{

  if ((res = ishpuxpkgvuln(pkg:"InternetSrvcs.INETSVCS-BOOT", patch_list:['PHNE_24512'], rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
