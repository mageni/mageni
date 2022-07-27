###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for java-1.6.0-openjdk RHSA-2010:0768-01
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
tag_insight = "These packages provide the OpenJDK 6 Java Runtime Environment and the
  OpenJDK 6 Software Development Kit.

  defaultReadObject of the Serialization API could be tricked into setting a
  volatile field multiple times, which could allow a remote attacker to
  execute arbitrary code with the privileges of the user running the applet
  or application. (CVE-2010-3569)
  
  Race condition in the way objects were deserialized could allow an
  untrusted applet or application to misuse the privileges of the user
  running the applet or application. (CVE-2010-3568)
  
  Miscalculation in the OpenType font rendering implementation caused
  out-of-bounds memory access, which could allow remote attackers to execute
  code with the privileges of the user running the java process.
  (CVE-2010-3567)
  
  JPEGImageWriter.writeImage in the imageio API improperly checked certain
  image metadata, which could allow a remote attacker to execute arbitrary
  code in the context of the user running the applet or application.
  (CVE-2010-3565)
  
  Double free in IndexColorModel could cause an untrusted applet or
  application to crash or, possibly, execute arbitrary code with the
  privileges of the user running the applet or application. (CVE-2010-3562)
  
  The privileged accept method of the ServerSocket class in the Common Object
  Request Broker Architecture (CORBA) implementation in OpenJDK allowed it to
  receive connections from any host, instead of just the host of the current
  connection. An attacker could use this flaw to bypass restrictions defined
  by network permissions. (CVE-2010-3561)
  
  Flaws in the Swing library could allow an untrusted application to modify
  the behavior and state of certain JDK classes. (CVE-2010-3557)
  
  Flaws in the CORBA implementation could allow an attacker to execute
  arbitrary code by misusing permissions granted to certain system objects.
  (CVE-2010-3554)
  
  UIDefault.ProxyLazyValue had unsafe reflection usage, allowing untrusted
  callers to create objects via ProxyLazyValue values. (CVE-2010-3553)
  
  HttpURLConnection improperly handled the &quot;chunked&quot; transfer encoding
  method, which could allow remote attackers to conduct HTTP response
  splitting attacks. (CVE-2010-3549)
  
  HttpURLConnection improperly checked whether the calling code was granted
  the &quot;allowHttpTrace&quot; permission, allowing untrusted code to create HTTP
  TRACE requests. (CVE-2010-3574)
  
  HttpURLConnection did not validate request headers set by applets, which
  could allow remote attackers to trigger actions otherwise res ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "java-1.6.0-openjdk on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-October/msg00014.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314441");
  script_version("$Revision: 8338 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-09 09:00:38 +0100 (Tue, 09 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-10-19 15:54:15 +0200 (Tue, 19 Oct 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2010:0768-01");
  script_cve_id("CVE-2009-3555", "CVE-2010-3541", "CVE-2010-3548", "CVE-2010-3549", "CVE-2010-3551", "CVE-2010-3553", "CVE-2010-3554", "CVE-2010-3557", "CVE-2010-3561", "CVE-2010-3562", "CVE-2010-3564", "CVE-2010-3565", "CVE-2010-3567", "CVE-2010-3568", "CVE-2010-3569", "CVE-2010-3573", "CVE-2010-3574", "CVE-2010-3566");
  script_name("RedHat Update for java-1.6.0-openjdk RHSA-2010:0768-01");

  script_tag(name: "summary" , value: "Check for the Version of java-1.6.0-openjdk");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-1.6.0.0", rpm:"java-1.6.0-openjdk-1.6.0.0~1.16.b17.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-debuginfo", rpm:"java-1.6.0-openjdk-debuginfo~1.6.0.0~1.16.b17.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~1.16.b17.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~1.16.b17.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~1.16.b17.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~1.16.b17.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
