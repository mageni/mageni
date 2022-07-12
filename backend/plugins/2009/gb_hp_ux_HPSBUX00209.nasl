###############################################################################
# OpenVAS Vulnerability Test
#
# HP-UX Update for DNS and Resolver Libraries HPSBUX00209
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
tag_impact = "Remote execution of arbitrary code or creation of a denial of service (DoS)";
tag_affected = "DNS and Resolver Libraries on
  HP-UX releases B.10.10, B.10.20, B.10.24 (VVOS), B.11.00, B.11.04 (VVOS), 
  B.11.11 and B.11.22.";
tag_insight = "A vulnerability in HP-UX DNS and resolver libraries which may allow remote 
  execution of arbitrary code or creation of a denial of service (DoS).";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c00957990-2");
  script_oid("1.3.6.1.4.1.25623.1.0.305687");
  script_version("$Revision: 6584 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 16:13:23 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-05-05 12:14:23 +0200 (Tue, 05 May 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "HPSBUX", value: "00209");
  script_name( "HP-UX Update for DNS and Resolver Libraries HPSBUX00209");

  script_tag(name:"summary", value:"Check for the Version of DNS and Resolver Libraries");
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

if(release == "HPUX10.10")
{

  if ((res = ishpuxpkgvuln(pkg:"InternetSrvcs.INETSVCS-RUN", patch_list:['PHNE_27792'], rls:"HPUX10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"OS-Core.CORE-SHLIBS", revision:".1.1010", rls:"HPUX10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.00")
{

  if ((res = ishpuxpkgvuln(pkg:"BINDv812.INETSVCS-BIND", revision:"B.11.00.01.004", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"BINDv920.INETSVCS-BIND", revision:"B.11.00.01.001", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"bind.INETSVCS-RUN", patch_list:['PHNE_28449'], rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"upgrade_bind812.INETSVCS-RUN", patch_list:['PHNE_28449'], rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"BINDv913.INETSVCS-BIND", patch_list:['PHNE_28449'], rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"InternetSrvcs.INETSVCS-RUN", patch_list:['PHNE_28449'], rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"NFS.NFS-SHLIBS", patch_list:['PHNE_27795'], rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"NFS.NFS-64SLIB", patch_list:['PHNE_27795'], rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX10.24")
{

  if ((res = ishpuxpkgvuln(pkg:"InternetSrvcs.INETSVCS-RUN", patch_list:['PHNE_27879'], rls:"HPUX10.24")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"OS-Core.C-MIN", patch_list:['PHCO_27882'], rls:"HPUX10.24")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"OS-Core.CORE-SHLIBS", patch_list:['PHCO_27882'], rls:"HPUX10.24")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"ProgSupport.PROG-AUX", patch_list:['PHCO_27882'], rls:"HPUX10.24")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"ProgSupport.PROG-MIN", patch_list:['PHCO_27882'], rls:"HPUX10.24")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.04")
{

  if ((res = ishpuxpkgvuln(pkg:"InternetSrvcs.INETSVCS-RUN", patch_list:['PHNE_29634'], rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"NFS.NFS-64SLIB", patch_list:['PHNE_27881'], rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"NFS.NFS-SHLIBS", patch_list:['PHNE_27881'], rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX10.20")
{

  if ((res = ishpuxpkgvuln(pkg:"InternetSrvcs.INETSVCS-RUN", patch_list:['PHNE_27792'], rls:"HPUX10.20")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"OS-Core.C-MIN", patch_list:['PHCO_26158'], rls:"HPUX10.20")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"OS-Core.CORE-SHLIBS", patch_list:['PHCO_26158'], rls:"HPUX10.20")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"ProgSupport.PROG-MIN", patch_list:['PHCO_26158'], rls:"HPUX10.20")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"ProgSupport.PROG-AUX", patch_list:['PHCO_26158'], rls:"HPUX10.20")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.22")
{

  if ((res = ishpuxpkgvuln(pkg:"InternetSrvcs.INETSVCS2-RUN", patch_list:['PHNE_28490'], rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"NFS.NFS-SHLIBS", patch_list:['PHNE_28299'], rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"NFS.NFS-64SLIB", patch_list:['PHNE_28299'], rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.11")
{

  if ((res = ishpuxpkgvuln(pkg:"BINDv913.INETSVCS-BIND", revision:"B.11.11.01.002", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"BIND.INETSVCS-RUN", revision:"B.11.11.01.002", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"BINDv920.INETSVCS-BIND", revision:"B.11.11.01.002", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"InternetSrvcs.INETSVCS-RUN", patch_list:['PHNE_28450'], rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"NFS.NFS-SHLIBS", patch_list:['PHNE_27796'], rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"NFS.NFS-64SLIB", patch_list:['PHNE_27796'], rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
