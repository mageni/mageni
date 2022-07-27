###############################################################################
# OpenVAS Vulnerability Test
#
# HP-UX Update for Apache with PHP HPSBUX02543
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
tag_impact = "Remote Denial of Service (DoS)
  unauthorized Access
  cross site scripting (XSS).";
tag_affected = "Apache with PHP on
  HP-UX B.11.11, B.11.23, B.11.31 running Apache with PHP v5.2.6 or earlier.";
tag_insight = "Potential security vulnerabilities have been identified with HP-UX running 
  Apache with PHP. These vulnerabilities could be exploited remotely to create 
  a Denial of Service (DoS) gain unauthorized access, and perform cross site 
  scripting (XSS).";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c02247738");
  script_oid("1.3.6.1.4.1.25623.1.0.313639");
  script_version("$Revision: 8457 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-06-23 12:17:53 +0200 (Wed, 23 Jun 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "HPSBUX", value: "02543");
  script_cve_id("CVE-2009-2687", "CVE-2009-3291", "CVE-2009-3292", "CVE-2009-3293", "CVE-2009-3557", "CVE-2009-4017", "CVE-2009-4018", "CVE-2009-4142", "CVE-2009-4143");
  script_name("HP-UX Update for Apache with PHP HPSBUX02543");

  script_tag(name: "summary" , value: "Check for the Version of Apache with PHP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

if(release == "HPUX11.31")
{

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.PHP", revision:"B.2.0.59.16", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.PHP2", revision:"B.2.0.59.16", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.PHP", revision:"B.2.0.59.16", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.PHP2", revision:"B.2.0.59.16", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APCH32.PHP", revision:"B.2.2.8.10", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APCH32.PHP2", revision:"B.2.2.8.10", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APACHE.PHP", revision:"B.2.2.8.10", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APACHE.PHP2", revision:"B.2.2.8.10", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.23")
{

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.PHP", revision:"B.2.0.59.16", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.PHP2", revision:"B.2.0.59.16", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.PHP", revision:"B.2.0.59.16", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.PHP2", revision:"B.2.0.59.16", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APCH32.PHP", revision:"B.2.2.8.10", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APCH32.PHP2", revision:"B.2.2.8.10", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APACHE.PHP", revision:"B.2.2.8.10", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APACHE.PHP2", revision:"B.2.2.8.10", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.11")
{

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.PHP", revision:"B.2.0.59.16", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.PHP2", revision:"B.2.0.59.16", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.PHP", revision:"B.2.0.59.16", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.PHP2", revision:"B.2.0.59.16", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}