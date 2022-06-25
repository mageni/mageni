###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows ATL COM Initialization Code Execution Vulnerability (973525)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-25
#  - To confirm Vulnerability on vista, win 2008 and win 7
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900880");
  script_version("2019-05-24T11:20:30+0000");
  script_cve_id("CVE-2009-2493");
  script_bugtraq_id(35828);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2009-10-14 18:36:58 +0200 (Wed, 14 Oct 2009)");
  script_name("Microsoft Windows ATL COM Initialization Code Execution Vulnerability (973525)");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/973525");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2890");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/MS09-055.mspx");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/972890.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attackers execute arbitrary code,
  and can compromise a vulnerable system.");

  script_tag(name:"affected", value:"Microsoft Windows 7

  Microsoft Windows 2K SP4/XP SP3/2K3 SP2 and prior

  Microsoft Windows Vista Service Pack 1/2 and prior

  Microsoft Windows Server 2008 Service Pack 1/2 and prior");

  script_tag(name:"insight", value:"The flaw is due to an error in the ATL headers that handle
  instantiation of an object from data streams, which could allow attackers to
  instantiate arbitrary objects in Internet Explorer that can bypass certain
  related security policies.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-055.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.

  As a workaround set the killbit for the following CLSIDs:

  {0002E531-0000-0000-C000-000000000046}, {4C85388F-1500-11D1-A0DF-00C04FC9E20F},
  {0002E532-0000-0000-C000-000000000046}, {0002E554-0000-0000-C000-000000000046},
  {0002E55C-0000-0000-C000-000000000046}, {279D6C9A-652E-4833-BEFC-312CA8887857},
  {B1F78FEF-3DB7-4C56-AF2B-5DCCC7C42331}, {C832BE8F-4B89-4579-A217-DB92E7A27915},
  {A9A7297E-969C-43F1-A1EF-51EBEA36F850}, {DD8C2179-1B4A-4951-B432-5DE3D1507142},
  {4F1E5B1A-2A80-42ca-8532-2D05CB959537}, {27A3D328-D206-4106-8D33-1AA39B13394B},
  {DB640C86-731C-484A-AAAF-750656C9187D}, {15721a53-8448-4731-8bfc-ed11e128e444},
  {3267123E-530D-4E73-9DA7-79F01D86A89F}");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_activex.inc");
include("secpod_reg.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, winVista:3, win7:1, win2008:3) <= 0){
  exit(0);
}

# MS09-055 Hotfix check
if(hotfix_missing(name:"973525") == 0){
  exit(0);
}

clsids = make_list(
  "{0002E531-0000-0000-C000-000000000046}", "{4C85388F-1500-11D1-A0DF-00C04FC9E20F}",
  "{0002E532-0000-0000-C000-000000000046}", "{0002E554-0000-0000-C000-000000000046}",
  "{0002E55C-0000-0000-C000-000000000046}", "{279D6C9A-652E-4833-BEFC-312CA8887857}",
  "{B1F78FEF-3DB7-4C56-AF2B-5DCCC7C42331}", "{C832BE8F-4B89-4579-A217-DB92E7A27915}",
  "{A9A7297E-969C-43F1-A1EF-51EBEA36F850}", "{DD8C2179-1B4A-4951-B432-5DE3D1507142}",
  "{4F1E5B1A-2A80-42ca-8532-2D05CB959537}", "{27A3D328-D206-4106-8D33-1AA39B13394B}",
  "{DB640C86-731C-484A-AAAF-750656C9187D}", "{15721a53-8448-4731-8bfc-ed11e128e444}",
  "{3267123E-530D-4E73-9DA7-79F01D86A89F}");

foreach clsid (clsids)
{
  if(is_killbit_set(clsid:clsid) == 0)
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
