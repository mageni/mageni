##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_detect_win.nasl 13901 2019-02-27 09:33:17Z cfischer $
#
# OpenSSL Version Detection (Windows)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800257");
  script_version("$Revision: 13901 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 10:33:17 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-04-02 08:15:32 +0200 (Thu, 02 Apr 2009)");
  script_name("OpenSSL Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"This script finds the installed OpenSSL version and saves the result in KB
  item.

  The script logs in via smb, searches for OpenSSL in the registry and gets the
  version from registry");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
  exit(0);

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list))
  exit(0);

foreach key(key_list) {

  foreach item(registry_enum_keys(key:key)) {

    sslname = registry_get_sz(key:key + item, item:"DisplayName");
    if("OpenSSL" >< sslname) {

      sslver = eregmatch(pattern:"([0-9]\.[0-9]\.[0-9.]+[a-z]?)", string:sslname);
      sslPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(sslver[1]) {

        set_kb_item(name:"openssl_or_gnutls/detected", value:TRUE);
        set_kb_item(name:"openssl/detected", value:TRUE);

        ## 64 bit apps on 64 bit platform
        if("x64" >< os_arch && "Wow6432Node" >!< key) {
          register_and_report_cpe(app:"OpenSSL", ver:sslver[0], base:"cpe:/a:openssl:openssl:x64:", expr:"^([0-9.]+[a-z]?)", insloc:sslPath, regPort:0, regService:"smb-login");
        } else {
          register_and_report_cpe(app:"OpenSSL", ver:sslver[0], base:"cpe:/a:openssl:openssl:", expr:"^([0-9.]+[a-z]?)", insloc:sslPath, regPort:0, regService:"smb-login");
        }
      }
    }
  }
}

exit(0);