###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for madwifi-source MDKSA-2007:082 (madwifi-source)
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
tag_insight = "The ath_rate_sample function in the ath_rate/sample/sample.c sample
  code in MadWifi before 0.9.3 allows remote attackers to cause a denial
  of service (failed KASSERT and system crash) by moving a connected
  system to a location with low signal strength, and possibly other
  vectors related to a race condition between interface enabling and
  packet transmission. (CVE-2005-4835)

  MadWifi, when Ad-Hoc mode is used, allows remote attackers to cause
  a denial of service (system crash) via unspecified vectors that lead
  to a kernel panic in the ieee80211_input function, related to packets
  coming from a malicious WinXP system. (CVE-2006-7177)
  
  MadWifi before 0.9.3 does not properly handle reception of an AUTH
  frame by an IBSS node, which allows remote attackers to cause a denial
  of service (system crash) via a certain AUTH frame. (CVE-2006-7178)
  
  ieee80211_input.c in MadWifi before 0.9.3 does not properly process
  Channel Switch Announcement Information Elements (CSA IEs), which
  allows remote attackers to cause a denial of service (loss of
  communication) via a Channel Switch Count less than or equal to one,
  triggering a channel change. (CVE-2006-7179)
  
  ieee80211_output.c in MadWifi before 0.9.3 sends unencrypted packets
  before WPA authentication succeeds, which allows remote attackers
  to obtain sensitive information (related to network structure),
  and possibly cause a denial of service (disrupted authentication)
  and conduct spoofing attacks. (CVE-2006-7180)
  
  Updated packages have been updated to 0.9.3 to correct this
  issue. Wpa_supplicant is built using madwifi-source and has been
  rebuilt using 0.9.3 source.";

tag_affected = "madwifi-source on Mandriva Linux 2007.0,
  Mandriva Linux 2007.0/X86_64,
  Mandriva Linux 2007.1,
  Mandriva Linux 2007.1/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-04/msg00017.php");
  script_oid("1.3.6.1.4.1.25623.1.0.309826");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 13:53:01 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_xref(name: "MDKSA", value: "2007:082");
  script_cve_id("CVE-2005-4835", "CVE-2006-7177", "CVE-2006-7178", "CVE-2006-7179", "CVE-2006-7180");
  script_name( "Mandriva Update for madwifi-source MDKSA-2007:082 (madwifi-source)");

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

  if ((res = isrpmvuln(pkg:"madwifi-source", rpm:"madwifi-source~0.9.3~1.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wpa_gui", rpm:"wpa_gui~0.5.7~1.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~0.5.7~1.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2007.0")
{

  if ((res = isrpmvuln(pkg:"madwifi-source", rpm:"madwifi-source~0.9.3~1.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wpa_gui", rpm:"wpa_gui~0.5.5~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~0.5.5~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
