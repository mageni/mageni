###############################################################################
# OpenVAS Vulnerability Test
#
# HP-UX Update for BIND v920 HPSBUX00290
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
tag_impact = "Remote Denial of Service (DoS)";
tag_affected = "BIND v920 on
  HP-UX B.11.00, B.11.11, B.11.22, and B.11.23, running BINDv920.";
tag_insight = "1. Certain ASN.1 encodings that are rejected as invalidby the parser can 
  trigger a bug in the deallocationof the corresponding data structure, 
  corrupting thestack. This can be used as a denial of serviceattack. It is 
  currently unknown whether this can beexploited to run malicious code. This 
  issue does notaffect OpenSSL 0.9.6.<br2. Unusual ASN.1 tag values can cause 
  an out of boundsread under certain circumstances, resulting in adenial of 
  service vulnerability.<br3. A malformed public key in a certificate will 
  crashthe verify code if it is set to ignore public keydecoding errors. 
  Exploitation of an affectedapplication would result in a denial of 
  servicevulnerability.<br4. Due to an error in the SSL/TLS protocol 
  handling,a server will parse a client certificate when one isnot 
  specifically requested.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c00901847-1");
  script_oid("1.3.6.1.4.1.25623.1.0.310449");
  script_version("$Revision: 6584 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 16:13:23 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-05-05 12:14:23 +0200 (Tue, 05 May 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "HPSBUX", value: "00290");
  script_cve_id("CVE-2003-0543", "CVE-2003-0544", "CVE-2003-0545");
  script_name( "HP-UX Update for BIND v920 HPSBUX00290");

  script_tag(name:"summary", value:"Check for the Version of BIND v920");
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

  if ((res = ishpuxpkgvuln(pkg:"BINDv920.INETSVCS-BIND", revision:"B.11.00.01.003", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.22")
{

  if ((res = ishpuxpkgvuln(pkg:"InternetSrvcs.INETSVCS2-RUN", patch_list:['PHNE_29859'], rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.11")
{

  if ((res = ishpuxpkgvuln(pkg:"BINDv920.INETSVCS-BIND", revision:"B.11.11.01.005", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.23")
{

  if ((res = ishpuxpkgvuln(pkg:"InternetSrvcs.INETSVCS2-RUN", patch_list:['PHNE_31726'], rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
