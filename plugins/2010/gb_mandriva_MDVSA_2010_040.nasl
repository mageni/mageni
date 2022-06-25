###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for gnome-screensaver MDVSA-2010:040 (gnome-screensaver)
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
tag_insight = "Multiple vulnerabilities has been discovered and corrected in
  gnome-screensaver:

  gnome-screensaver 2.28.0 does not resume adherence to its activation
  settings after an inhibiting application becomes unavailable on the
  session bus, which allows physically proximate attackers to access
  an unattended workstation on which screen locking had been intended
  (CVE-2009-4641).
  
  gnome-screensaver before 2.28.2 allows physically proximate attackers
  to bypass screen locking and access an unattended workstation by moving
  the mouse position to an external monitor and then disconnecting that
  monitor (CVE-2010-0414).
  
  This update provides gnome-screensaver 2.28.3, which is not vulnerable
  to these issues.";

tag_affected = "gnome-screensaver on Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-02/msg00036.php");
  script_oid("1.3.6.1.4.1.25623.1.0.313003");
  script_version("$Revision: 8457 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-02-19 13:38:15 +0100 (Fri, 19 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2010:040");
  script_cve_id("CVE-2009-4641", "CVE-2010-0414");
  script_name("Mandriva Update for gnome-screensaver MDVSA-2010:040 (gnome-screensaver)");

  script_tag(name: "summary" , value: "Check for the Version of gnome-screensaver");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"gnome-screensaver", rpm:"gnome-screensaver~2.28.3~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
