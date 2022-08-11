###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxmail_detect.nasl 11376 2018-09-13 12:51:39Z cfischer $
#
# FoxMail Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800219");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11376 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:51:39 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-01-08 14:06:04 +0100 (Thu, 08 Jan 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("FoxMail Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl", "gb_wmi_access.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "WMI/access_successful");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script finds the installed FoxMail Version and saves in KB.");

  script_tag(name:"qod_type", value:"registry");
  exit(0);
}

CPE = "cpe:/a:tencent:foxmail:";

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("secpod_smb_func.inc");
include("wmi_file.inc");
include("misc_func.inc");

foreach keypart( make_list_unique( "Foxmail_is1", "Foxmail", registry_enum_keys( key: "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" ),
  registry_enum_keys( key: "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" ) ) ) {

  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + keypart;
  if( ! registry_key_exists( key: key ) ) {
    key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" + keypart;
    if( ! registry_key_exists( key: key ) ) continue;
  }

  name = registry_get_sz( key: key, item: "DisplayName" );
  if( "Foxmail" >!< name ) continue;
  set_kb_item( name: "foxmail/detected", value: TRUE );

  version = "unknown";

  loc = registry_get_sz( key: key, item: "UninstallString" );
  if( ! isnull( loc ) ){
    loc = ereg_replace( pattern: '(uninst(all)?\\.exe)', string: loc, replace: '', icase: TRUE );

    file_path = loc + 'Foxmail.exe';
    escaped_file_path = ereg_replace( pattern: "\\", string: file_path, replace: "\\" );

    host    = get_host_ip();
    usrname = kb_smb_login();
    passwd  = kb_smb_password();

    if( host && usrname && passwd ) {

      domain = kb_smb_domain();
      if( domain ) usrname = domain + '\\' + usrname;

      handle = wmi_connect( host: host, username: usrname, password: passwd );
      if( handle ) {
        versList = wmi_file_fileversion( handle: handle, filePath: escaped_file_path, includeHeader:FALSE );
        if( versList && is_array( versList ) ) {
          foreach vers( keys( versList ) ) {
            if( versList[vers] && version = eregmatch( string:versList[vers], pattern:"([0-9.]+)" ) ) {
              version = vers;
              set_kb_item( name:"Foxmail/Win/Ver", value:version );
              break;
            }
          }
        }
        wmi_close( wmi_handle: handle );
      }
    }
  }

  register_and_report_cpe( app: "Tencent Foxmail",
                           ver: version,
                           concluded: name,
                           base: CPE,
                           expr: '([0-9.]+)',
                           insloc: loc );
  break;
}
exit(0);
