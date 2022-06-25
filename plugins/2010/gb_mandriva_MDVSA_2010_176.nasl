###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for tomcat5 MDVSA-2010:176 (tomcat5)
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
tag_insight = "Multiple vulnerabilities has been found and corrected in tomcat5:

  Apache Tomcat 6.0.0 through 6.0.14, 5.5.0 through 5.5.25, and 4.1.0
  through 4.1.36 does not properly handle (1) double quote (&quot;) characters
  or (2) \%5C (encoded backslash) sequences in a cookie value, which
  might cause sensitive information such as session IDs to be leaked
  to remote attackers and enable session hijacking attacks.  NOTE:
  this issue exists because of an incomplete fix for CVE-2007-3385
  (CVE-2007-5333).
  
  Apache Tomcat 4.1.0 through 4.1.39, 5.5.0 through 5.5.27, 6.0.0 through
  6.0.18, and possibly earlier versions normalizes the target pathname
  before filtering the query string when using the RequestDispatcher
  method, which allows remote attackers to bypass intended access
  restrictions and conduct directory traversal attacks via .. (dot dot)
  sequences and the WEB-INF directory in a Request (CVE-2008-5515).
  
  Apache Tomcat 4.1.0 through 4.1.39, 5.5.0 through 5.5.27, and 6.0.0
  through 6.0.18, when the Java AJP connector and mod_jk load balancing
  are used, allows remote attackers to cause a denial of service
  (application outage) via a crafted request with invalid headers,
  related to temporary blocking of connectors that have encountered
  errors, as demonstrated by an error involving a malformed HTTP Host
  header (CVE-2009-0033).
  
  Apache Tomcat 4.1.0 through 4.1.39, 5.5.0 through 5.5.27, and
  6.0.0 through 6.0.18, when FORM authentication is used, allows
  remote attackers to enumerate valid usernames via requests to
  /j_security_check with malformed URL encoding of passwords, related to
  improper error checking in the (1) MemoryRealm, (2) DataSourceRealm,
  and (3) JDBCRealm authentication realms, as demonstrated by a \%
  (percent) value for the j_password parameter (CVE-2009-0580).
  
  Apache Tomcat 4.1.0 through 4.1.39, 5.5.0 through 5.5.27, and 6.0.0
  through 6.0.18 permits web applications to replace an XML parser used
  for other web applications, which allows local users to read or modify
  the (1) web.xml, (2) context.xml, or (3) tld files of arbitrary web
  applications via a crafted application that is loaded earlier than
  the target application (CVE-2009-0783).
  
  Directory traversal vulnerability in Apache Tomcat 5.5.0 through
  5.5.28 and 6.0.0 through 6.0.20 allows remote attackers to create or
  overwrite arbitrary files via a .. (dot dot) in an entry in a WAR file,
  as demonstrated by a ../../bin/catalina.bat entry (CVE-2009-2693).
  
  The autodeployment process in Apache Tomcat 5.5.0 through 5.5.28 a ... 

  Description truncated, for more information please check the Reference URL";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "tomcat5 on Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-09/msg00010.php");
  script_oid("1.3.6.1.4.1.25623.1.0.314051");
  script_version("$Revision: 8246 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-26 08:29:20 +0100 (Tue, 26 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-09-14 15:35:55 +0200 (Tue, 14 Sep 2010)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_xref(name: "MDVSA", value: "2010:176");
  script_cve_id("CVE-2007-3385", "CVE-2007-5333", "CVE-2008-5515", "CVE-2009-0033", "CVE-2009-0580", "CVE-2009-0783", "CVE-2009-2693", "CVE-2009-2901", "CVE-2009-2902", "CVE-2010-1157", "CVE-2010-2227");
  script_name("Mandriva Update for tomcat5 MDVSA-2010:176 (tomcat5)");

  script_tag(name: "summary" , value: "Check for the Version of tomcat5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"tomcat5", rpm:"tomcat5~5.5.23~9.2.10.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-admin-webapps", rpm:"tomcat5-admin-webapps~5.5.23~9.2.10.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-common-lib", rpm:"tomcat5-common-lib~5.5.23~9.2.10.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-jasper", rpm:"tomcat5-jasper~5.5.23~9.2.10.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-jasper-javadoc", rpm:"tomcat5-jasper-javadoc~5.5.23~9.2.10.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-jsp-2.0-api", rpm:"tomcat5-jsp-2.0-api~5.5.23~9.2.10.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-jsp-2.0-api-javadoc", rpm:"tomcat5-jsp-2.0-api-javadoc~5.5.23~9.2.10.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-server-lib", rpm:"tomcat5-server-lib~5.5.23~9.2.10.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-servlet-2.4-api", rpm:"tomcat5-servlet-2.4-api~5.5.23~9.2.10.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-servlet-2.4-api-javadoc", rpm:"tomcat5-servlet-2.4-api-javadoc~5.5.23~9.2.10.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat5-webapps", rpm:"tomcat5-webapps~5.5.23~9.2.10.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
