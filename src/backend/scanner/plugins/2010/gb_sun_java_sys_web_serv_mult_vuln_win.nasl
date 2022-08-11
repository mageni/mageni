###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_sys_web_serv_mult_vuln_win.nasl 12978 2019-01-08 14:15:07Z cfischer $
#
# Sun Java System Web Server Multiple Vulnerabilities (Windows)
#
# Authors:
# Veerendra G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800157");
  script_version("$Revision: 12978 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-08 15:15:07 +0100 (Tue, 08 Jan 2019) $");
  script_tag(name:"creation_date", value:"2010-02-04 12:53:38 +0100 (Thu, 04 Feb 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0360", "CVE-2010-0361", "CVE-2010-0387");
  script_bugtraq_id(37896);
  script_name("Sun Java System Web Server Multiple Vulnerabilities (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://intevydis.com/sjws_demo.html");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/55792");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Jan/1023488.html");
  script_xref(name:"URL", value:"http://intevydis.blogspot.com/2010/01/sun-java-system-web-server-70u7-webdav.html");
  script_xref(name:"URL", value:"http://intevydis.blogspot.com/2010/01/sun-java-system-web-server-70u7-digest.html");

  script_tag(name:"impact", value:"Successful exploitation lets the attackers to discover process memory
  locations or execute arbitrary code in the context of an affected system
  or cause the application to crash via a long URI in an HTTP OPTIONS request.");

  script_tag(name:"affected", value:"Sun Java System Web Server version 7.0 update 7 on Windows.");

  script_tag(name:"insight", value:"- An error exists in WebDAV implementation in webservd and can be exploited
  to cause Stack-based buffer overflow via long URI in an HTTP OPTIONS request.

  - An unspecified error that can be exploited to cause a heap-based buffer
  overflow which allows remote attackers to discover process memory
  locations and execute arbitrary code by sending a process memory address
  via crafted data.

  - An error exists in in webservd and admin server that can be exploited to
  overflow a buffer and execute arbitrary code on the system or cause
  the server to crash via a long string in an 'Authorization: Digest' HTTP
  header.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host has Sun Java Web Server running which is prone to
  multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
sjswsPath = registry_get_sz( key:key + "Sun Java System Web Server", item:"UninstallString" );
if( ! sjswsPath ) exit( 0 );

sjswsPath = ereg_replace( pattern:'\"(.*)\"', replace:"\1", string:sjswsPath );
sjswsPath = sjswsPath - "\bin\uninstall.exe" + "\setup\WebServer.inf";
fileData = smb_read_file(fullpath:sjswsPath, offset:0, count:500 );
if( ! fileData ) exit( 0 );

sjswsVer = eregmatch(pattern:"PRODUCT_VERSION=([0-9.]+)", string:fileData);
sjswsUpdateVer = eregmatch(pattern:"PRODUCT_SP_VERSION=([0-9]+)", string:fileData);

if( ! isnull( sjswsVer[1] ) ) {
  if( ! isnull( sjswsUpdateVer ) ) {
    sjswsFullVer = sjswsVer[1] + "." + sjswsUpdateVer[1];
  } else {
    sjswsFullVer = sjswsVer[1] + "." + "0";
  }
}

if( sjswsFullVer ) {
  if( version_is_equal( version:sjswsFullVer, test_version:"7.0.7" ) ) {
    report = report_fixed_ver( installed_version:sjswsFullVer, fixed_version:"WillNotFix", file_checked:sjswsPath );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );