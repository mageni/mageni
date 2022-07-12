###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ecava_integraxor_66554.nasl 12095 2018-10-25 12:00:24Z cfischer $
#
# Ecava IntegraXor Account Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103934");
  script_bugtraq_id(66554);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 12095 $");

  script_name("Ecava IntegraXor Account Information Disclosure Vulnerability");


  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66554");
  script_xref(name:"URL", value:"http://www.integraxor.com/");

  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:00:24 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-04-03 13:12:18 +0200 (Thu, 03 Apr 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Attackers can exploit this issue to obtain sensitive information that
may lead to further attacks.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Updates are available.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Ecava IntegraXor is prone to an information-disclosure vulnerability.");
  script_tag(name:"affected", value:"Versions prior to IntegraXor 4.1.4393 are vulnerable.");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ecavaigName = registry_get_sz(key:key + item, item:"DisplayName");

  if("IntegraXor" >< ecavaigName)
  {
    ecavaigVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(ecavaigVer != NULL)
    {
      if(version_is_less(version:ecavaigVer, test_version:"4.1.4393"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

