##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_trendmicro_officescan_auth_bypass_vuln_900205.nasl 14192 2019-03-14 14:54:41Z cfischer $
# Description: Trend Micro Web Management Authentication Bypass Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900205");
  script_version("$Revision: 14192 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 15:54:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-08-27 11:53:45 +0200 (Wed, 27 Aug 2008)");
  script_bugtraq_id(30792);
  script_cve_id("CVE-2008-2433");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Privilege escalation");
  script_name("Trend Micro Web Management Authentication Bypass Vulnerability");
  script_dependencies("gb_trend_micro_office_scan_detect.nasl");
  script_mandatory_keys("Trend/Micro/Officescan/Ver");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://secunia.com/advisories/31373/");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Aug/1020732.html");
  script_xref(name:"URL", value:"http://www.trendmicro.com/ftp/products/patches/OSCE_8.0_SP1_Win_EN_CriticalPatch_B2402.exe");
  script_xref(name:"URL", value:"http://www.trendmicro.com/ftp/products/patches/OSCE_8.0_Win_EN_CriticalPatch_B1351.exe");
  script_xref(name:"URL", value:"http://www.trendmicro.com/ftp/products/patches/OSCE_8.0_SP1_Patch1_Win_EN_CriticalPatch_B3037.exe");
  script_xref(name:"URL", value:"http://www.trendmicro.com/ftp/products/patches/WFBS_50_WIN_EN_CriticalPatch_B1404.exe");

  script_tag(name:"summary", value:"This Remote host is installed with Trend Micro OfficeScan, which
  is prone to Authentication Bypass Vulnerability.");

  script_tag(name:"insight", value:"The flaw is due to insufficient entropy in a random session
  token used to identify an authenticated manager using the web console.");

  script_tag(name:"affected", value:"Trend Micro Client Server Messaging Security (CSM) versions 3.5 and 3.6

  Trend Micro OfficeScan Corporate Edition versions 7.0 and 7.3

  Trend Micro OfficeScan Corporate Edition version 8.0

  Trend Micro Worry-Free Business Security (WFBS) version 5.0");

  script_tag(name:"solution", value:"Partially Fixed.
  Fix is available for Trend Micro OfficeScan 8.0 and Worry-Free Business Security 5.0.");

  script_tag(name:"impact", value:"Remote users can gain administrative access on the target
  application and allow arbitrary code execution.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");

scanVer = registry_get_sz(key:"SOFTWARE\TrendMicro\OfficeScan\service\Information", item:"Server_Version");
if(!scanVer)
  exit(0);

if(egrep(pattern:"^([0-7]\..*|8\.0)$", string:scanVer)){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);