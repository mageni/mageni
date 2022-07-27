###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for madwifi-source MDKSA-2007:132 (madwifi-source)
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
tag_insight = "The 802.11 network stack in MadWifi prior to 0.9.3.1 would alloa remote
  attackers to cause a denial of service (system hang) via a crafted
  length field in nested 802.3 Ethernet frames in Fast Frame packets,
  which results in a NULL pointer dereference (CVE-2007-2829).

  The ath_beacon_config function in MadWifi prior to 0.9.3.1 would
  allow a remote attacker to cause a denial of service (system crash)
  via crafted beacon interval information when scanning for access
  points, which triggered a divide-by-zero error (CVE-2007-2830).
  
  An array index error in MadWifi prior to 0.9.3.1 would allow a
  local user to cause a denial of service (system crash) and possibly
  obtain kerenl memory contents, as well as possibly allowing for the
  execution of arbitrary code via a large negative array index value
  (CVE-2007-2831).
  
  Updated packages have been updated to 0.9.3.1 to correct these
  issues. Wpa_supplicant is built using madwifi-source and has been
  rebuilt using 0.9.3.1 source.";

tag_affected = "madwifi-source on Mandriva Linux 2007.0,
  Mandriva Linux 2007.0/X86_64,
  Mandriva Linux 2007.1,
  Mandriva Linux 2007.1/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-06/msg00034.php");
  script_oid("1.3.6.1.4.1.25623.1.0.306927");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 13:57:01 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDKSA", value: "2007:132");
  script_cve_id("CVE-2007-2829", "CVE-2007-2830", "CVE-2007-2831", "CVE-2006-2830", "CVE-2006-2831");
  script_name( "Mandriva Update for madwifi-source MDKSA-2007:132 (madwifi-source)");

  script_tag(name:"summary", value:"Check for the Version of madwifi-source");
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

  if ((res = isrpmvuln(pkg:"madwifi-source", rpm:"madwifi-source~0.9.3.1~1.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wpa_gui", rpm:"wpa_gui~0.5.7~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~0.5.7~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2007.0")
{

  if ((res = isrpmvuln(pkg:"madwifi-source", rpm:"madwifi-source~0.9.3.1~1.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wpa_gui", rpm:"wpa_gui~0.5.5~2.2mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~0.5.5~2.2mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
