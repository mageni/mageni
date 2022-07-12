###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for tog-pegasus RHSA-2008:1001-01
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
tag_insight = "The tog-pegasus packages provide OpenPegasus Web-Based Enterprise
  Management (WBEM) services. WBEM is a platform and resource independent
  Distributed Management Task Force (DMTF) standard that defines a common
  information model and communication protocol for monitoring and controlling
  resources.

  Red Hat defines additional security enhancements for OpenGroup Pegasus WBEM
  services in addition to those defined by the upstream OpenGroup Pegasus
  release. For details regarding these enhancements, refer to the file
  &quot;README.RedHat.Security&quot;, included in the Red Hat tog-pegasus package.
  
  After re-basing to version 2.7.0 of the OpenGroup Pegasus code, these
  additional security enhancements were no longer being applied. As a
  consequence, access to OpenPegasus WBEM services was not restricted to the
  dedicated users as described in README.RedHat.Security. An attacker able to
  authenticate using a valid user account could use this flaw to send
  requests to WBEM services. (CVE-2008-4313)
  
  Note: default SELinux policy prevents tog-pegasus from modifying system
  files. This flaw's impact depends on whether or not tog-pegasus is confined
  by SELinux, and on any additional CMPI providers installed and enabled on a
  particular system.
  
  Failed authentication attempts against the OpenPegasus CIM server were not
  logged to the system log as documented in README.RedHat.Security. An
  attacker could use this flaw to perform password guessing attacks against a
  user account without leaving traces in the system log. (CVE-2008-4315)
  
  All tog-pegasus users are advised to upgrade to these updated packages,
  which contain patches to correct these issues.";

tag_affected = "tog-pegasus on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-November/msg00016.html");
  script_oid("1.3.6.1.4.1.25623.1.0.307946");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2008:1001-01");
  script_cve_id("CVE-2008-4313", "CVE-2008-4315");
  script_name( "RedHat Update for tog-pegasus RHSA-2008:1001-01");

  script_tag(name:"summary", value:"Check for the Version of tog-pegasus");
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"tog-pegasus", rpm:"tog-pegasus~2.7.0~2.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tog-pegasus-debuginfo", rpm:"tog-pegasus-debuginfo~2.7.0~2.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tog-pegasus-devel", rpm:"tog-pegasus-devel~2.7.0~2.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
