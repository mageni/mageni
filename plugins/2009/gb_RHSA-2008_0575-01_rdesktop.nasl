###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for rdesktop RHSA-2008:0575-01
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
tag_insight = "rdesktop is an open source client for Microsoft Windows NT Terminal Server
  and Microsoft Windows 2000 and 2003 Terminal Services, capable of natively
  using the Remote Desktop Protocol (RDP) to present the user's NT desktop.
  No additional server extensions are required.

  An integer underflow and integer signedness issue were discovered in the
  rdesktop. If an attacker could convince a victim to connect to a malicious
  RDP server, the attacker could cause the victim's rdesktop to crash or,
  possibly, execute an arbitrary code. (CVE-2008-1801, CVE-2008-1803)
  
  Users of rdesktop should upgrade to these updated packages, which contain a
  backported patches to resolve these issues.";

tag_affected = "rdesktop on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-July/msg00027.html");
  script_oid("1.3.6.1.4.1.25623.1.0.306263");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2008:0575-01");
  script_cve_id("CVE-2008-1801", "CVE-2008-1803");
  script_name( "RedHat Update for rdesktop RHSA-2008:0575-01");

  script_tag(name:"summary", value:"Check for the Version of rdesktop");
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

  if ((res = isrpmvuln(pkg:"rdesktop", rpm:"rdesktop~1.4.1~6", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rdesktop-debuginfo", rpm:"rdesktop-debuginfo~1.4.1~6", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
