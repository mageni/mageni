###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vaadin_javascript_inj_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Vaadin Javascript Injection
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH

# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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

CPE = 'cpe:/a:vaadin:vaadin';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107226");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-23 12:00:00 +0100 (Fri, 23 Jun 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");


  script_name("Vaadin Javascript Injection");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_vaadin_detect.nasl");
  script_require_ports("Services/www", 8888);
  script_mandatory_keys("vaadin/installed");

  script_tag(name:"summary", value:"This web application is running with the Vaadin Framework which is prone to a Vaadin Javascript Injection vulnerability");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The exploit is due to inappropriate rendering in the combobox.");
  script_tag(name:"impact", value:"Successful exploiting this vulnerability will allow an attacker to inject malicious javascript code.");
  script_tag(name:"affected", value:"Vaadin Framework versions 7.7.6 to 7.7.9");
  script_tag(name:"solution", value:"Upgrade Vaadin at least to version 8.x.");

  script_xref(name:"URL", value:"https://github.com/vaadin/framework/issues/8731");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Jun/27");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"7.7.6", test_version2:"7.7.9" ) ) {

  report = report_fixed_ver(installed_version: vers, fixed_version: "8.0.2");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
