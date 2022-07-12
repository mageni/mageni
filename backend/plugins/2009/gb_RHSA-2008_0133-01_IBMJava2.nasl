###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for IBMJava2 RHSA-2008:0133-01
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
tag_insight = "IBM's 1.3.1 Java release includes the IBM Java 2 Runtime Environment and
  the IBM Java 2 Software Development Kit.

  A buffer overflow was found in the Java Runtime Environment image-handling
  code. An untrusted applet or application could use this flaw to elevate its
  privileges and potentially execute arbitrary code as the user running the
  java virtual machine. (CVE-2007-3004)
  
  An unspecified vulnerability was discovered in the Java Runtime
  Environment. An untrusted applet or application could cause the java
  virtual machine to become unresponsive. (CVE-2007-3005)
  
  A flaw was found in the applet class loader. An untrusted applet could use
  this flaw to circumvent network access restrictions, possibly connecting to
  services hosted on the machine that executed the applet. (CVE-2007-3922)
  
  These updated packages also add the following enhancements:
  
  * Time zone information has been updated to the latest available
  information, 2007h.
  
  * Accessibility support in AWT can now be disabled through a system
  property, java.assistive.  To support this change,  permission to read this
  property must be added to /opt/IBMJava2-131/jre/lib/security/java.policy.
  Users of IBMJava2 who have modified this file should add this following
  line to the grant section:
  
  permission java.util.PropertyPermission &quot;java.assistive&quot;, &quot;read&quot;;
  
  All users of IBMJava2 should upgrade to these updated packages, which
  contain IBM's 1.3.1 SR11 Java release, which resolves these issues.";

tag_affected = "IBMJava2 on Red Hat Enterprise Linux AS (Advanced Server) version 2.1,
  Red Hat Enterprise Linux ES version 2.1,
  Red Hat Enterprise Linux WS version 2.1";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-June/msg00018.html");
  script_oid("1.3.6.1.4.1.25623.1.0.311803");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2008:0133-01");
  script_cve_id("CVE-2007-3922", "CVE-2007-2789", "CVE-2007-2788");
  script_name( "RedHat Update for IBMJava2 RHSA-2008:0133-01");

  script_tag(name:"summary", value:"Check for the Version of IBMJava2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

if(release == "RHENT_2.1")
{

  if ((res = isrpmvuln(pkg:"IBMJava2-JRE", rpm:"IBMJava2-JRE~1.3.1~17", rls:"RHENT_2.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"IBMJava2-SDK", rpm:"IBMJava2-SDK~1.3.1~17", rls:"RHENT_2.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
