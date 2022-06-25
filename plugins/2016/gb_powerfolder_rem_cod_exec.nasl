###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_powerfolder_rem_cod_exec.nasl 9564 2018-04-23 09:32:17Z asteins $
#
# PowerFolder Remote Code Execution Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa..at..greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = 'cpe:/a:powerfolder:powerfolder';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107010");
  script_version("$Revision: 9564 $");

  script_tag(name:"last_modification", value:"$Date: 2018-04-23 11:32:17 +0200 (Mon, 23 Apr 2018) $");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"creation_date", value:"2016-06-07 06:40:16 +0200 (Tue, 07 Jun 2016)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("PowerFolder Remote Code Execution Vulnerability");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39854/");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/137172/PowerFolder-10.4.321-Remote-Code-Execution.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_powerfolder_detection.nasl");
  script_mandatory_keys("powerfolder/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"PowerFolder version 10.4.321 suffers from a remote code execution vulnerability.");
  script_tag(name:"insight", value:"The data exchange method between PowerFolder server and clients allows deserialization of untrusted data, which can be exploited to execute arbitrary code.");
  script_tag(name:"impact", value:"Successful exploitation allows an attacker unauthorized disclosure of information, unauthorized modification and disruption of service.");
  script_tag(name:"affected", value:"PowerFolder 10.4.321 (Linux/Windows) (Other version might be also affected).");
  script_tag(name:"solution", value:"Update PowerFolder to version 10 SP5 (10.5.394) or later.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( !appPort = get_app_port( cpe:CPE)) exit( 0 );
if ( !appVer = get_app_version( cpe:CPE, port: appPort) ) exit( 0 );

if ( version_is_less_equal(version:appVer, test_version:"10.4.321" ) )
{
  report = report_fixed_ver( installed_version: appVer, fixed_version: "10 SP5 (10.5.394)" );
  security_message( port: appPort, data: report );
  exit( 0 );
}

exit( 99 );
