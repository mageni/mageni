###############################################################################
# OpenVAS Vulnerability Test
#
# HP-UX Update for Apache-based Web Server HPSBUX02465
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
  unauthorized access";
tag_affected = "Apache-based Web Server on
  HP-UX B.11.23, B.11.31 running Apache-based Web Server versions before
  v2.2.8.05 HP-UX B.11.11, B.11.23, B.11.31 running Apache-based Web Server
  versions before v2.0.59.12";
tag_insight = "Potential security vulnerabilities have been identified with HP-UX running
  Apache-based Web Server. The vulnerabilities could be exploited remotely to
  cause a Denial of Service (DoS), cross-site scripting (XSS) or unauthorized
  access. Apache-based Web Server is contained in the Apache Web Server Suite.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c01905287-1");
  script_oid("1.3.6.1.4.1.25623.1.0.312111");
  script_version("$Revision: 6584 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 16:13:23 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-10-22 15:43:41 +0200 (Thu, 22 Oct 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "HPSBUX", value: "02465");
  script_cve_id("CVE-2006-3918", "CVE-2007-4465", "CVE-2007-6203", "CVE-2008-0005", "CVE-2008-0599", "CVE-2008-2168", "CVE-2008-2364", "CVE-2008-2371", "CVE-2008-2665", "CVE-2008-2666", "CVE-2008-2829", "CVE-2008-2939", "CVE-2008-3658", "CVE-2008-3659", "CVE-2008-3660", "CVE-2008-5498", "CVE-2008-5557", "CVE-2008-5624", "CVE-2008-5625", "CVE-2008-5658");
  script_name("HP-UX Update for Apache-based Web Server HPSBUX02465");

  script_tag(name:"summary", value:"Check for the Version of Apache-based Web Server");
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

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APCH32.APACHE", revision:"B.2.2.8.05", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APCH32.APACHE2", revision:"B.2.2.8.05", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APCH32.AUTH_LDAP", revision:"B.2.2.8.05", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APCH32.AUTH_LDAP2", revision:"B.2.2.8.05", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APCH32.MOD_JK", revision:"B.2.2.8.05", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APCH32.MOD_JK2", revision:"B.2.2.8.05", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APCH32.MOD_PERL", revision:"B.2.2.8.05", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APCH32.MOD_PERL2", revision:"B.2.2.8.05", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APCH32.PHP", revision:"B.2.2.8.05", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APCH32.PHP2", revision:"B.2.2.8.05", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APCH32.WEBPROXY", revision:"B.2.2.8.05", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APCH32.WEBPROXY2", revision:"B.2.2.8.05", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.APACHE", revision:"B.2.0.59.12", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.APACHE2", revision:"B.2.0.59.12", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.AUTH_LDAP", revision:"B.2.0.59.12", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.AUTH_LDAP2", revision:"B.2.0.59.12", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.MOD_JK", revision:"B.2.0.59.12", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.MOD_JK2", revision:"B.2.0.59.12", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.MOD_PERL", revision:"B.2.0.59.12", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.MOD_PERL2", revision:"B.2.0.59.12", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.PHP", revision:"B.2.0.59.12", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.PHP2", revision:"B.2.0.59.12", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.WEBPROXY", revision:"B.2.0.59.12", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.23")
{

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APACHE.APACHE", revision:"B.2.2.8.05", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APACHE.APACHE2", revision:"B.2.2.8.05", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APACHE.AUTH_LDAP", revision:"B.2.2.8.05", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APACHE.AUTH_LDAP2", revision:"B.2.2.8.05", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APACHE.MOD_JK", revision:"B.2.2.8.05", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APACHE.MOD_JK2", revision:"B.2.2.8.05", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APACHE.MOD_PERL", revision:"B.2.2.8.05", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APACHE.MOD_PERL2", revision:"B.2.2.8.05", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APACHE.PHP", revision:"B.2.2.8.05", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxws22APACHE.PHP2", revision:"B.2.2.8.05", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.APACHE", revision:"B.2.0.59.12", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.APACHE2", revision:"B.2.0.59.12", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.AUTH_LDAP", revision:"B.2.0.59.12", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.AUTH_LDAP2", revision:"B.2.0.59.12", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.MOD_JK", revision:"B.2.0.59.12", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.MOD_JK2", revision:"B.2.0.59.12", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.MOD_PERL", revision:"B.2.0.59.12", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.MOD_PERL2", revision:"B.2.0.59.12", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.PHP", revision:"B.2.0.59.12", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.PHP2", revision:"B.2.0.59.12", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.WEBPROXY", revision:"B.2.0.59.12", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.11")
{

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.APACHE", revision:"B.2.0.59.12", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.APACHE2", revision:"B.2.0.59.12", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.AUTH_LDAP2", revision:"B.2.0.59.12", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.MOD_JK", revision:"B.2.0.59.12", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.MOD_JK2", revision:"B.2.0.59.12", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.MOD_PERL", revision:"B.2.0.59.12", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.MOD_PERL2", revision:"B.2.0.59.12", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.PHP", revision:"B.2.0.59.12", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.PHP2", revision:"B.2.0.59.12", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"hpuxwsAPACHE.WEBPROXY", revision:"B.2.0.59.12", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
