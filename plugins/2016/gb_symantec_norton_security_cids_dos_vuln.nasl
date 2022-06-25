###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_norton_security_cids_dos_vuln.nasl 11782 2018-10-08 14:01:44Z cfischer $
#
# Symantec Norton Security 'CIDS' Driver Denial of Service Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:symantec:norton_security";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808624");
  script_version("$Revision: 11782 $");
  script_cve_id("CVE-2016-5308");
  script_bugtraq_id(91608);
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-08 16:01:44 +0200 (Mon, 08 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-10-07 13:20:51 +0530 (Fri, 07 Oct 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Symantec Norton Security 'CIDS' Driver Denial of Service Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Symantec
  Norton Security and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the client intrusion
  detection system (CIDS) driver is improperly handling a malformed PE executable
  file.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause a denial of service (memory corruption and system crash).");

  script_tag(name:"affected", value:"Symantec Norton Security CIDS Drivers
  prior to version 15.1.2.");

  script_tag(name:"solution", value:"Update Symantec Norton Security through
  LiveUpdate.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160707_01");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_symantec_norton_security_detect.nasl");
  script_mandatory_keys("Symantec/Norton/Security/Ver");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("wmi_file.inc");

if( ! get_app_version( cpe:CPE ) ) exit( 0 );

infos = kb_smb_wmi_connectinfo();
if( ! infos ) exit( 0 );

handle = wmi_connect( host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"] );
if( ! handle ) exit( 0 );

# TODO: Limit to a possible known common path, maybe from the Detection-NVT?
fileList = wmi_file_fileversion( handle:handle, fileName:"IDSvix86", fileExtn:"sys", includeHeader:FALSE );
wmi_close( wmi_handle:handle );
if( ! fileList || ! is_array( fileList ) ) {
  exit( 0 );
}

foreach filePath( keys( fileList ) ) {

  vers = fileList[filePath];

  if( vers && version = eregmatch( string:vers, pattern:"^([0-9.]+)" ) ) {

    if( version_is_less( version:version[1], test_version:"15.1.2" ) ) {
      report = report_fixed_ver( file_version:version[1], file_checked:filePath, fixed_version:"15.1.2" );
      security_message( port:0, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );