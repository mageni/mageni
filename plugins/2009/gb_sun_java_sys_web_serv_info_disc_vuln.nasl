###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_sys_web_serv_info_disc_vuln.nasl 12978 2019-01-08 14:15:07Z cfischer $
#
# Sun Java System Web Server '.jsp' Information Disclosure Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800658");
  script_version("$Revision: 12978 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-08 15:15:07 +0100 (Tue, 08 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-07-22 21:36:53 +0200 (Wed, 22 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-2445");
  script_bugtraq_id(35577);
  script_name("Sun Java System Web Server '.jsp' Information Disclosure Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35701");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1022511");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1786");

  script_tag(name:"impact", value:"Successful exploitation will lets the attackers to execute
  arbitrary code, gain sensitive information.");

  script_tag(name:"affected", value:"Sun Java System Web Server versions 6.1 and before 6.1 SP11
  and Sun Java System Web Server versions 7.0 update 5 on Windows.");

  script_tag(name:"insight", value:"This issue is caused by an error when handling requests to JSP
  files with the '.jsp::$DATA' string appended to the file extension, which
  could be exploited by remote attackers to display the source code of arbitrary
  JSP files instead of an expected HTML response.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Sun Java Web Server which is prone to
  Information Disclosure Vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if( ! registry_key_exists( key:"SOFTWARE\Sun Microsystems\WebServer" ) ) exit( 0 );

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if( ! registry_key_exists( key:key ) ) exit( 0 );

foreach item( registry_enum_keys( key:key ) ) {
  jswsName = registry_get_sz( key:key + item, item:"DisplayName" );
  if( jswsName && jswsName =~ "Sun (ONE |Java System )Web Server" ) {
    jswsVer = eregmatch( pattern:"Web Server ([0-9.]+)(SP[0-9]+)?", string:jswsName );
    if( ! isnull( jswsVer[1] ) ) {
      if( ! isnull( jswsVer[2] ) ) {
        jswsVer = jswsVer[1] + "." + jswsVer[2];
      } else {
        jswsVer = jswsVer[1];
      }
      break;
    }
  }
}

if( ! jswsVer ) {
  jswsPath = registry_get_sz( key:key + "Sun Java System Web Server", item:"UninstallString" );
  if( ! jswsPath ) exit( 0 );

  jswsPath = ereg_replace( pattern:'\"(.*)\"', replace:"\1", string:jswsPath );
  jswsPath = jswsPath - "\bin\uninstall.exe" + "\README.TXT";
  jswsVer = smb_read_file(fullpath:jswsPath, offset:0, count:150 );
  if( ! jswsVer ) exit( 0 );

  jswsVer = eregmatch( pattern:"Web Server ([0-9.]+)([ a-zA-z]+)?([0-9]+)?", string:jswsVer );
  if( ! isnull( jswsVer[1] ) ) {
    file_checked = jswsPath;
    if( ! isnull( jswsVer[3] ) ) {
      jswsVer = jswsVer[1] + "." + jswsVer[3];
    } else {
      jswsVer = jswsVer[1];
    }
  }
}

if( jswsVer && jswsVer =~ "^[67]" ) {
  if( version_in_range( version:jswsVer, test_version:"6.1", test_version2:"6.1.SP11" ) ||
      version_in_range( version:jswsVer, test_version:"7.0", test_version2:"7.0.5" ) ) {
    report = report_fixed_ver( installed_version:jswsVer, fixed_version:"WillNotFix", file_checked:file_checked );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );