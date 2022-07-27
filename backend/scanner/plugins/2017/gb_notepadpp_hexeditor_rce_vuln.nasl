###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_notepadpp_hexeditor_rce_vuln.nasl 12043 2018-10-23 14:16:52Z mmartin $
#
# Notepad++ Hex Editor Plugin Buffer Overflow Vulnerability
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

CPE = "cpe:/a:don_ho:notepad++";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811586");
  script_version("$Revision: 12043 $");
  script_cve_id("CVE-2017-8803");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-23 16:16:52 +0200 (Tue, 23 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-22 14:00:19 +0530 (Tue, 22 Aug 2017)");
  script_name("Notepad++ Hex Editor Plugin Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_notepadpp_detect_portable_win.nasl");
  script_mandatory_keys("Notepad++32/Win/installed");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"https://github.com/wlinzi/security_advisories/tree/master/CVE-2017-8803");

  script_tag(name:"summary", value:"The host is installed with Notepad++
  and is prone to a Buffer Overflow Vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version of Notepad++ and the Hex Editor Plugin
  is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a 'Data from Faulting
  Address controls Code Flow' issue in Hex Editor in Notepad++.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  user-assisted attackers to execute code via a crafted file.");

  script_tag(name:"affected", value:"Notepad++ version 7.3.3 (32-bit) with
  Hex Editor Plugin v0.9.5 on Windows.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if( vers != "7.3.3" || ! path || "Could not find the install location from registry" >< path ) exit( 0 );
if( ! dllVer = fetch_file_version( sysPath:path, file_name:"plugins\hexeditor.dll" ) ) exit( 0 );

if( dllVer == "0.9.5.0" ) {
  report = report_fixed_ver( installed_version:"Notepad++ version " + vers + ", Hex Editor version" + dllVer, fixed_version:"NoneAvailable" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
