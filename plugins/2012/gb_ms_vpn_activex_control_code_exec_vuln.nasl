###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft VPN ActiveX Control Remote Code Execution Vulnerability (2695962)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802774");
  script_version("2019-05-03T12:31:27+0000");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-05-10 11:55:58 +0530 (Thu, 10 May 2012)");
  script_name("Microsoft VPN ActiveX Control Remote Code Execution Vulnerability (2695962)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2695962");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/advisory/2695962#section8");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120314-asaclient");
  script_cve_id("CVE-2012-0358");
  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes on the
  affected machine.");

  script_tag(name:"affected", value:"Microsoft Windows 7 Service Pack 1 and prior

  Microsoft Windows XP Service Pack 3 and prior

  Microsoft Windows 2003 Service Pack 2 and prior

  Microsoft Windows Vista Service Pack 2 and prior

  Microsoft Windows Server 2008 Service Pack 2 and prior

  Microsoft Windows XP Service Pack 2 and prior for x64-based Systems

  Microsoft Windows Server 2008 R2 Service Pack 1 and prior for x64-based Systems");

  script_tag(name:"insight", value:"The flaw is due to Cisco Adaptive Security Appliances (Cisco ASA),
  uses an ActiveX control on client systems to perform port forwarding
  operations. Microsoft ActiveX technology may be affected if the system has
  ever connected to a device that is running the Cisco Clientless VPN solution.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is installed with Cisco Adaptive Security Appliance and
  is prone to ActiveX control remote code execution vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_activex.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(is_killbit_set(clsid:"{B8E73359-3422-4384-8D27-4EA1B4C01232}") == 0){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
