###############################################################################
# OpenVAS Vulnerability Test
#
# HP-UX Update for Apache Web Server Suite HPSBUX02401
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
tag_impact = "Remote Denial of Service (DoS)
  cross-site scripting (XSS)
  execution of arbitrary code
  cross-site request forgery (CSRF)";
tag_affected = "Apache Web Server Suite on
  HP-UX B.11.23 and B.11.31 running Apache-based Web Server v2.2.8.01.01 or 
  v2.0.59.07.02 or earlier or Tomcat-based Servelet Engine v5.5.27.01 or 
  earlier HP-UX B.11.11 running Apache-based Web Server v2.0.59.07.02 or 
  earlier or Tomcat-based Servelet Engine v5.5.27.01 or earlier";
tag_insight = "Potential security vulnerabilities have been identified with HP-UX running 
  Apache-based Web Server or Tomcat-based Servelet Engine. The vulnerabilities 
  could be exploited remotely to cause a Denial of Service (DoS), cross-site 
  scripting (XSS), execution of arbitrary code, or cross-site request forgery 
  (CSRF). Apache-based Web Server and Tomcat-based Servelet Engine are 
  contained in the Apache Web Server Suite.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c01650939-4");
  script_oid("1.3.6.1.4.1.25623.1.0.308090");
  script_version("$Revision: 6584 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 16:13:23 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-05-05 12:14:23 +0200 (Tue, 05 May 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "HPSBUX", value: "02401");
  script_cve_id("CVE-2007-6420", "CVE-2008-1232", "CVE-2008-1947", "CVE-2008-2364", "CVE-2008-2370", "CVE-2008-2938", "CVE-2008-2939", "CVE-2008-3658");
  script_name( "HP-UX Update for Apache Web Server Suite HPSBUX02401");

  script_tag(name:"summary", value:"Check for the Version of Apache Web Server Suite");
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

if(release == "HPUX11.31")
{

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APACHE.APACHE", revision:"B.2.2.8.01.02", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APACHE.APACHE2", revision:"B.2.2.8.01.02", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22TOMCAT.TOMCAT", revision:"B.2.2.8.01.02", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.APACHE", revision:"B.2.0.59.07.03", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.APACHE2", revision:"B.2.0.59.07.03", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsTOMCAT.TOMCAT", revision:"B.2.0.59.07.03", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.23")
{

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APCH32.APACHE", revision:"B.2.2.8.01.02", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APCH32.APACHE2", revision:"B.2.2.8.01.02", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22TOMCAT.TOMCAT", revision:"B.2.2.8.01.02", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.APACHE", revision:"B.2.0.59.07.03", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPCH32.APACHE2", revision:"B.2.0.59.07.03", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsTOMCAT.TOMCAT", revision:"B.2.0.59.07.03", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.11")
{

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.APACHE", revision:"B.2.0.59.07.03", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.APACHE2", revision:"B.2.0.59.07.03", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsTOMCAT.TOMCAT", revision:"B.2.0.59.07.03", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
