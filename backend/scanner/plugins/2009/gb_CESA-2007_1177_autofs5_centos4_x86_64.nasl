###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for autofs5 CESA-2007:1177 centos4 x86_64
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
  automatically mounts file systems when you use them, and unmounts them when
  you are not using them. This can include network file systems and CD-ROMs.
  The autofs5 packages were made available as a technology preview in Red Hat
  Enterprise Linux 4.6.

  There was a security issue with the default configuration of autofs version
  5, whereby the entry for the &quot;-hosts&quot; map did not specify the &quot;nodev&quot; mount
  option. A local user with control of a remote NFS server could create
  special device files on the remote file system, that if mounted using the
  default &quot;-hosts&quot; map, could allow the user to access important system
  devices. (CVE-2007-6285)
  
  This issue is similar to CVE-2007-5964, which fixed a missing &quot;nosuid&quot;
  mount option in autofs. Both the &quot;nodev&quot; and &quot;nosuid&quot; options should be
  enabled to prevent a possible compromise of machine integrity.
  
  Due to the fact that autofs always mounted &quot;-hosts&quot; map entries &quot;dev&quot; by
  default, autofs has now been altered to always use the &quot;nodev&quot; option when
  mounting from the default &quot;-hosts&quot; map. The &quot;dev&quot; option must be explicitly
  given in the master map entry to revert to the old behavior. This change
  affects only the &quot;-hosts&quot; map which corresponds to the &quot;/net&quot; entry in the
  default configuration.
  
  All autofs5 users are advised to upgrade to these updated packages, which
  resolve this issue.
  
  Red Hat would like to thank Tim Baum for reporting this issue.";

tag_affected = "autofs5 on CentOS 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2007-December/014545.html");
  script_oid("1.3.6.1.4.1.25623.1.0.311186");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 08:31:09 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-6285", "CVE-2007-5964");
  script_name( "CentOS Update for autofs5 CESA-2007:1177 centos4 x86_64");

  script_tag(name:"summary", value:"Check for the Version of autofs5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"autofs5", rpm:"autofs5~5.0.1~0.rc2.55.el4_6.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
