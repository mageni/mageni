###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for autofs MDVSA-2008:009-1 (autofs)
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
tag_insight = "The default behaviour of autofs 5 for the hosts map did not specify the
  nosuid and nodev mount options.  This could allow a local user with
  control of a remote NFS server to create a setuid root executable on
  the exported filesystem of the remote NFS server.  If this filesystem
  was mounted with the default hosts map, it would allow the user to
  obtain root privileges (CVE-2007-5964).  Likewise, the same scenario
  would be available for local users able to create device files on
  the exported filesystem which could allow the user to gain access to
  important system devices (CVE-2007-6285).

  Because the default behaviour of autofs was to mount -hosts map
  entries with the dev and suid options enabled by default, autofs has
  been altered to always use nodev and nosuid by default.  In order
  to have the old behaviour, the configuration must now explicitly set
  the dev and/or suid options.
  
  This change only affects the -hosts map which corresponds to the /net
  entry in the default configuration.
  
  Update:
  
  The previous update shipped with an incorrect LDAP lookup module
  that would prevent the automount daemon from starting.  This update
  corrects that problem.";

tag_affected = "autofs on Mandriva Linux 2007.1,
  Mandriva Linux 2007.1/X86_64,
  Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-01/msg00021.php");
  script_oid("1.3.6.1.4.1.25623.1.0.310896");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:26:37 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2008:009-1");
  script_cve_id("CVE-2007-5964", "CVE-2007-6285");
  script_name( "Mandriva Update for autofs MDVSA-2008:009-1 (autofs)");

  script_tag(name:"summary", value:"Check for the Version of autofs");
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

if(release == "MNDK_2007.1")
{

  if ((res = isrpmvuln(pkg:"autofs", rpm:"autofs~5.0.2~8.4mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"autofs", rpm:"autofs~5.0.2~8.4mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
