###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_98022.nasl 12021 2018-10-22 14:54:51Z mmartin $
#
# Joomla! CVE-2017-7988 Security Bypass Vulnerability
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108154");
  script_version("$Revision: 12021 $");
  script_cve_id("CVE-2017-7988");
  script_bugtraq_id(98022);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 16:54:51 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-08 10:00:00 +0200 (Mon, 08 May 2017)");
  script_name("Joomla! CVE-2017-7988 Security Bypass Vulnerability");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/688-20170406-core-acl-violations");

  script_tag(name:"summary", value:"This host is running Joomla and is prone
  to a security-bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to inadequate filtering of form contents.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to bypass certain security
  restrictions and perform unauthorized actions. This may aid in launching further attacks.");

  script_tag(name:"affected", value:"Joomla core versions 1.6.0 through 3.6.5");

  script_tag(name:"solution", value:"Upgrade to Joomla version 3.7.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.joomla.org");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"1.6.0", test_version2:"3.6.5" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.7.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
