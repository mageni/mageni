###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_prdts_activex_mult_vuln.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# Cisco Products ActiveX Control Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802459");
  script_version("$Revision: 14117 $");
  script_cve_id("CVE-2012-2493", "CVE-2012-2494", "CVE-2012-2495");
  script_bugtraq_id(54107, 54108);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-09-12 13:30:28 +0530 (Wed, 12 Sep 2012)");
  script_name("Cisco Products ActiveX Control Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/advisory/2736233");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=26196");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=26197");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=26198");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=26199");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120620-ac");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attackers execute arbitrary code
  and can compromise a vulnerable system.");

  script_tag(name:"affected", value:"Cisco Hostscan version 3.x before 3.0 MR8

  Cisco AnyConnect VPN before 3.0 MR8 (3.0.08057)

  Cisco AnyConnect Secure Mobility Client version 2.x before 2.5 MR6 and 3.x before 3.0 MR8 on Windows");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An insufficient validation of input by the Cisco AnyConnect Secure Mobility
    Client WebLaunch component.

  - An improper sanitization of user-supplied input by the affected software's
    download feature.");

  script_tag(name:"summary", value:"This host is installed with Cisco ASMC/Hostscan/Secure Desktop or
  Cisco ActiveX controls and is prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to AnyConnect 3.0 MR8 (3.0.08057), Hostscan 3.0 MR8 (3.0.08062)
  and Cisco Secure Desktop 3.6.6020 or later.

  Workaround:
  Set the killbit for the following CLSIDs:

  {705ec6d4-b138-4079-a307-ef13e4889a82}

  {f8fc1530-0608-11df-2008-0800200c9a66}

  {e34f52fe-7769-46ce-8f8b-5e8abad2e9fc}

  {55963676-2f5e-4baf-ac28-cf26aa587566}

  {cc679cb8-dc4b-458b-b817-d447b3b6ac31}


  *****
  NOTE: Ignore this warning, if upgraded to above mentioned versions.
  *****");

  exit(0);
}

include("smb_nt.inc");
include("secpod_activex.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

clsids = make_list("{705ec6d4-b138-4079-a307-ef13e4889a82}",
                   "{f8fc1530-0608-11df-2008-0800200c9a66}",
                   "{e34f52fe-7769-46ce-8f8b-5e8abad2e9fc}",
                   "{55963676-2f5e-4baf-ac28-cf26aa587566}",
                   "{cc679cb8-dc4b-458b-b817-d447b3b6ac31}");

foreach clsid (clsids)
{
  if(is_killbit_set(clsid:clsid) == 0)
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
