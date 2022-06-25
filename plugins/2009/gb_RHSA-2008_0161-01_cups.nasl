###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for cups RHSA-2008:0161-01
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
tag_insight = "The Common UNIX Printing System (CUPS) provides a portable printing layer
  for UNIX(R) operating systems.

  A flaw was found in the way CUPS handled the addition and removal of remote
  shared printers via IPP.  A remote attacker could send malicious UDP IPP
  packets causing the CUPS daemon to attempt to dereference already freed
  memory and crash. (CVE-2008-0597)
  
  A memory management flaw was found in the way CUPS handled the addition and
  removal of remote shared printers via IPP.  When shared printer was
  removed, allocated memory was not properly freed, leading to a memory leak
  possibly causing CUPS daemon crash after exhausting available memory.
  (CVE-2008-0596)
  
  These issues were found during the investigation of CVE-2008-0882, which
  did not affect Red Hat Enterprise Linux 4.
  
  Note that the default configuration of CUPS on Red Hat Enterprise Linux
  4 allow requests of this type only from the local subnet.
  
  All CUPS users are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues.";

tag_affected = "cups on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-February/msg00015.html");
  script_oid("1.3.6.1.4.1.25623.1.0.310548");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2008:0161-01");
  script_cve_id("CVE-2008-0596", "CVE-2008-0597", "CVE-2008-0882");
  script_name( "RedHat Update for cups RHSA-2008:0161-01");

  script_tag(name:"summary", value:"Check for the Version of cups");
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

if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.1.22~0.rc1.9.20.2.el4_6.5", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-debuginfo", rpm:"cups-debuginfo~1.1.22~0.rc1.9.20.2.el4_6.5", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~1.1.22~0.rc1.9.20.2.el4_6.5", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.1.22~0.rc1.9.20.2.el4_6.5", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
