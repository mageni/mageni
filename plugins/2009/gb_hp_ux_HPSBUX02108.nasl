###############################################################################
# OpenVAS Vulnerability Test
#
# HP-UX Update for sendmail HPSBUX02108
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
tag_impact = "Remote execution of arbitrary code";
tag_affected = "sendmail on
  HP-UX B.11.23 running sendmail 8.13.3, sendmail 8.11.1 HP-UX B.11.11 running 
  sendmail 8.13.3, sendmail 8.11.1, sendmail 8.9.3 HP-UX B.11.04 running 
  sendmail 8.9.3 HP-UX B.11.00 running sendmail 8.11.1, sendmail 8.9.3, 
  sendmail 8.8.6";
tag_insight = "A vulnerability has been identified in sendmailwhich may allow a remote 
  attacker to execute arbitrary code.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c00629555-11");
  script_oid("1.3.6.1.4.1.25623.1.0.305854");
  script_version("$Revision: 6584 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 16:13:23 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-05-05 12:14:23 +0200 (Tue, 05 May 2009)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_xref(name: "HPSBUX", value: "02108");
  script_cve_id("CVE-2006-0058");
  script_name( "HP-UX Update for sendmail HPSBUX02108");

  script_tag(name:"summary", value:"Check for the Version of sendmail");
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

  if ((res = ishpuxpkgvuln(pkg:"SMAIL-811.INETSVCS-SMAIL", revision:"B.11.00.01.009", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"UNOF_INET_29773_1.INETSVCS-RUN", patch_list:['PHNE_35483'], rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"UNOF_INET_29773_2.INETSVCS-RUN", patch_list:['PHNE_35483'], rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"UNOF_INET_29773_3.INETSVCS-RUN", patch_list:['PHNE_35483'], rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"InternetSrvcs.INETSVCS-RUN", patch_list:['PHNE_35483'], rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"UNOF_INET_29773_1.INETSVCS-RUN", patch_list:['PHNE_35483'], rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"UNOF_INET_29773_2.INETSVCS-RUN", patch_list:['PHNE_35483'], rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"UNOF_INET_29773_3.INETSVCS-RUN", patch_list:['PHNE_35483'], rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"InternetSrvcs.INETSVCS-RUN", patch_list:['PHNE_35483'], rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.23")
{

  if ((res = ishpuxpkgvuln(pkg:"SMAIL-UPGRADE.INET-SMAIL", revision:"B.11.11.02.004", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"SMAIL-UPGRADE.INET2-SMAIL", revision:"B.11.11.02.004", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"SMAIL-UPGRADE.INETSVCS-SMAIL", revision:"B.11.11.02.004", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"UNOF_INET31734_1.INETSVCS2-RUN", patch_list:['PHNE_35485'], rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"UNOF_INET31734_3.INETSVCS2-RUN", patch_list:['PHNE_35485'], rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"UNOF_INET31734_4.INETSVCS2-RUN", patch_list:['PHNE_35485'], rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"InternetSrvcs.INETSVCS2-RUN", patch_list:['PHNE_35485'], rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.04")
{

  if ((res = ishpuxpkgvuln(pkg:"UNOF_INET_29773_1.INETSVCS-RUN", patch_list:['PHNE_34927'], rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"UNOF_INET_29773_2.INETSVCS-RUN", patch_list:['PHNE_34927'], rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"UNOF_INET_29773_3.INETSVCS-RUN", patch_list:['PHNE_34927'], rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"InternetSrvcs.INETSVCS-RUN", patch_list:['PHNE_34927'], rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.11")
{

  if ((res = ishpuxpkgvuln(pkg:"SMAIL-UPGRADE.INET-SMAIL", revision:"B.11.11.02.004", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"SMAIL-UPGRADE.INET2-SMAIL", revision:"B.11.11.02.004", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"SMAIL-UPGRADE.INETSVCS-SMAIL", revision:"B.11.11.02.004", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"SMAIL-811.INETSVCS-SMAIL", revision:"B.11.11.01.010", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"UNOF_INET_29774_1.INETSVCS-RUN", patch_list:['PHNE_35484'], rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"UNOF_INET_29774_2.INETSVCS-RUN", patch_list:['PHNE_35484'], rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"UNOF_INET_29774_3.INETSVCS-RUN", patch_list:['PHNE_35484'], rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"InternetSrvcs.INETSVCS-RUN", patch_list:['PHNE_35484'], rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
