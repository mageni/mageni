###############################################################################
# OpenVAS Vulnerability Test
#
# Dell SonicWALL Secure Mobile Access - Cross-Site Scripting / Cross-Site Request Forgery Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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

CPE = "cpe:/o:dell:sonicwall_secure_mobile_access";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107119");
  script_version("2019-05-10T14:24:23+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-10 14:24:23 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2017-01-09 13:26:09 +0700 (Mon, 09 Jan 2017)");
  script_tag(name:"qod_type", value:"remote_app");
  script_name("Dell SonicWALL Secure Mobile Access - Cross-Site Scripting / Cross-Site Request Forgery Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Dell SonicWALL Secure Mobile Access and prone to Cross-Site Scripting / Cross-Site Request Forgery
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"SonicWALL SMA suffers from an XSS issue due to a failure to properly sanitize
  user-supplied input to several parameters.");

  script_tag(name:"impact", value:"Attackers can exploit this weakness to execute arbitrary HTML and script code
  in a user's browser session. The WAF was bypassed via form-based CSRF.");

  script_tag(name:"affected", value:"Dell SonicWALL Secure Mobile Access SMA 8.1 below 8.1.0.3.");

  script_tag(name:"solution", value:"Update Dell SonicWALL Secure Mobile Access SMA to 8.1.0.3.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40978/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dell_sonicwall_sma_detection.nasl");
  script_mandatory_keys("sonicwall/sma/detected", "sonicwall/sma/series");
  script_require_udp_ports("Services/udp/snmp", 161);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! series = get_kb_item( "sonicwall/sma/series" ) ) exit( 0 );

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( ( series == "200" || series == "400" || series == "500v" ) && version_in_range( version:version, test_version:"8.1", test_version2:"8.1.0.2" ) ) {

  report = report_fixed_ver( installed_version:version, fixed_version:"8.1.0.3" );
  security_message( port:0, data:report );

  exit( 0 );
}

exit( 99 );
