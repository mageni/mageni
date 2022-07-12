###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freeswitch_mult_bof_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# FreeSWITCH 'switch_regex.c' Multiple Buffer Overflow Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:freeswitch:freeswitch";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804025");
  script_version("$Revision: 11401 $");
  script_cve_id("CVE-2013-2238");
  script_bugtraq_id(60890);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-10-07 18:52:44 +0530 (Mon, 07 Oct 2013)");
  script_name("FreeSWITCH 'switch_regex.c' Multiple Buffer Overflow Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_freeswitch_detect.nasl");
  script_mandatory_keys("FreeSWITCH/installed");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q3/10");
  script_xref(name:"URL", value:"http://jira.freeswitch.org/browse/FS-5566");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2013/07/04/4");

  script_tag(name:"summary", value:"This host is installed with FreeSWITCH and is prone to multiple buffer overflow
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"insight", value:"Flaw is due to improper validation of user supplied input when handling the
  'index[]' variable or when handling 'substituted' variables in switch_regex.c script.");

  script_tag(name:"affected", value:"FreeSWITCH version 1.2");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to cause multiple buffer
  overflows, resulting in a denial of service.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) ) exit( 0 );

version = infos["version"];
proto = infos["proto"];

if( version_is_equal( version: version, test_version:"1.2.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"No fix available" );
  security_message( port:port, data:report, protocol:proto );
  exit( 0 );
}

exit( 99 );
