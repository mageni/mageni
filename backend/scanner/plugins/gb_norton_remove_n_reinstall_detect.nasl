###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_norton_remove_n_reinstall_detect.nasl 13953 2019-03-01 08:57:48Z cfischer $
#
# Norton Remove and Reinstall Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812213");
  script_version("$Revision: 13953 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 09:57:48 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-11-07 18:05:25 +0530 (Tue, 07 Nov 2017)");
  script_name("Norton Remove  and Reinstall Detection");
  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_wmi_access.nasl");
  script_mandatory_keys("WMI/access_successful");
  script_exclude_keys("win/lsc/disable_wmi_search");

  script_tag(name:"summary", value:"Detects the installed version of
  Norton Remove & Reinstall.

  The script logs in via smb and gets the version from Norton Remove & Reinstall
  file 'NRnR.exe'.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");

if( get_kb_item( "win/lsc/disable_wmi_search" ) )
  exit( 0 );

infos = kb_smb_wmi_connectinfo();
if( ! infos )
  exit( 0 );

handle = wmi_connect( host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"] );
if( ! handle )
  exit( 0 );

query = 'Select Manufacturer, Version from CIM_DataFile Where FileName ='
        + raw_string(0x22) + 'NRnR' + raw_string(0x22) + ' AND Extension ='
        + raw_string(0x22) + 'exe' + raw_string(0x22);
appConfirm = wmi_query( wmi_handle:handle, query:query );
wmi_close( wmi_handle:handle );

if("Symantec Corporation" >< appConfirm)
{
  version = eregmatch( pattern:"Symantec Corporation\|(.*)rnr.exe.?([0-9.]+)", string:appConfirm );
  if(version[2])
  {
    if(version[1]){
      path = version[1];
    } else{
        path = "Couldn find the install location.";
      }

    set_kb_item( name:"Norton/Remove/Reinstall/Win/Ver", value:version[2] );

    cpe = build_cpe(value:version[2], exp:"^([0-9.]+)", base:"cpe:/a:norton:remove_%26_reinstall:");
    if(isnull(cpe))
      cpe = "cpe:/a:norton:remove_%26_reinstall ";

    register_product(cpe:cpe, location:path);

    log_message(data:build_detection_report(app:"Norton Remove and Reinstall",
                                              version:version[2],
                                              install:path,
                                              cpe:cpe,
                                              concluded:version[2]));
  }
}

exit( 0 );