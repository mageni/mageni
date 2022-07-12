###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_apic_em_83105.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# Cisco Application Policy Infrastructure Controller Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:cisco:application_policy_infrastructure_controller_enterprise_module";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105537");
  script_bugtraq_id(83105);
  script_cve_id("CVE-2016-1318");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 12313 $");

  script_name("Cisco Application Policy Infrastructure Controller  Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83105");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160208-apic");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability is due to insufficient input validation of user-submitted content.");
  script_tag(name:"solution", value:"See vendor advisory");
  script_tag(name:"summary", value:"Cisco Application Policy Infrastructure Controller is prone to a cross-site scripting vulnerability.");
  script_tag(name:"affected", value:"Cisco APIC-EM version 1.1 is affected.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # advisory is very vague about effected versions

  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-02-11 14:46:59 +0100 (Thu, 11 Feb 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_apic_em_web_detect.nasl");
  script_require_ports("Services/www", 80, 443);
  script_mandatory_keys("cisco/apic_em/version");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

if( vers =  get_app_version( cpe:CPE, port:port ) )
{
  if( vers =~ "^1\.1" ) # # advisory is very vague about effected versions
  {
    report = report_fixed_ver(  installed_version:vers, fixed_version:'See vendor advisory' );
    security_message( port:port, data:report );
    exit(0 );
  }
}

exit( 99 );
