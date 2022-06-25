###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for autofs5 RHSA-2007:1129-01
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
tag_insight = "The autofs utility controls the operation of the automount daemon, which
  automatically mounts and unmounts file systems after a period of
  inactivity.  The autofs version 5 package was made available as a
  technology preview in Red Hat Enterprise Linux version 4.6.

  There was a security issue with the default installed configuration of
  autofs version 5 whereby the entry for the &quot;hosts&quot; map did not specify the
  &quot;nosuid&quot; mount option. A local user with control of a remote nfs server
  could create a setuid root executable within an exported filesystem on the
  remote nfs server that, if mounted using the default hosts map, would allow
  the user to gain root privileges. (CVE-2007-5964)
  
  Due to the fact that autofs version 5 always mounted hosts map entries suid
  by default, autofs has now been altered to always use the &quot;nosuid&quot; option
  when mounting from the default hosts map. The &quot;suid&quot; option must be
  explicitly given in the master map entry to revert to the old behavior.
  This change affects only the hosts map which corresponds to the /net entry
  in the default configuration.
  
  Users are advised to upgrade to these updated autofs5 packages, which
  resolve this issue.
  
  Red Hat would like to thank Josh Lange for reporting this issue.";

tag_affected = "autofs5 on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2007-December/msg00010.html");
  script_oid("1.3.6.1.4.1.25623.1.0.308255");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2007:1129-01");
  script_cve_id("CVE-2007-5964");
  script_name( "RedHat Update for autofs5 RHSA-2007:1129-01");

  script_tag(name:"summary", value:"Check for the Version of autofs5");
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

  if ((res = isrpmvuln(pkg:"autofs5", rpm:"autofs5~5.0.1~0.rc2.55.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"autofs5-debuginfo", rpm:"autofs5-debuginfo~5.0.1~0.rc2.55.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
