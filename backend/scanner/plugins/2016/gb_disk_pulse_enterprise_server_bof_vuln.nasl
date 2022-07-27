##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_disk_pulse_enterprise_server_bof_vuln.nasl 12363 2018-11-15 09:51:15Z asteins $
#
# Disk Pulse Enterprise Server Buffer Overflow Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:diskpulse:diskpulse_enterprise_web_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809057");
  script_version("$Revision: 12363 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-10-05 16:17:52 +0530 (Wed, 05 Oct 2016)");
  script_name("Disk Pulse Enterprise Server Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_disk_pulse_enterprise_server_detect.nasl");
  script_mandatory_keys("DiskPulse/Enterprise/Server/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://www.diskpulse.com");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40835/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40758/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40452/");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/138959");

  script_tag(name:"summary", value:"The host is running Disk Pulse Enterprise
  Server and is prone to buffer overflow vulnerability.

  This NVT has been replaced by NVT 'Disk Pulse Enterprise Server Buffer Overflow Vulnerability' (OID: 1.3.6.1.4.1.25623.1.0.809484).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error when processing
  web requests and can be exploited to cause a buffer overflow via an overly long
  string passed to 'Login' request.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote
  attackers to cause the application to crash, creating a denial-of-service
  condition.");

  script_tag(name:"affected", value:"Disk Pulse Enterprise version 9.1.16 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less_equal( version:vers, test_version:"9.1.16" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None Available" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
