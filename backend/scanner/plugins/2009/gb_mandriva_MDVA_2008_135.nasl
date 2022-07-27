###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for draksnapshot MDVA-2008:135 (draksnapshot)
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
tag_insight = "This update fixes several issues in draksnapshot:

  The draksnapshot applet received the following fixes:
  
  - on desktop startup, it will wait for 30s before checking for
  available disc so that notification is positioned at the right place,
  on the applet icon
  - it prevents crashing if DBus is not reachable, and reports DBus
  errors
  - it prevents crashing if DBus is active, but HAL is not (#44434)
  - if all discs are unmounted, the applet will hide (#41176)
  - it prevents running more than once
  - it uses HAL in order to detect discs available for backup, thus
  fixing detecting some internal SATA discs as discs available for backup
  (#41107)
  
  It also uses new icons from Mandriva Linux 2009.0.
  
  The draksnapshot configuration tool also received the following fixes:
  
  - it stops saving config when clicking Close (#39790); one has to
  click on Apply in order to save the config
  - on first run, it offers backup in mounted disc path, instead of
  defaulting to some place in the root filesystem which could previously
  be filled up (#39802)
  - it no longer offers to configure some obscure advanced options
  - it now allows for disabling backups
  - it generates anacron-friendly cron files";

tag_affected = "draksnapshot on Mandriva Linux 2008.1,
  Mandriva Linux 2008.1/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-10/msg00008.php");
  script_oid("1.3.6.1.4.1.25623.1.0.304486");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:09:08 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVA", value: "2008:135");
  script_name( "Mandriva Update for draksnapshot MDVA-2008:135 (draksnapshot)");

  script_tag(name:"summary", value:"Check for the Version of draksnapshot");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
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

if(release == "MNDK_2008.1")
{

  if ((res = isrpmvuln(pkg:"draksnapshot", rpm:"draksnapshot~0.19~2.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
