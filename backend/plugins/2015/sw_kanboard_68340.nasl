###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_kanboard_68340.nasl 14184 2019-03-14 13:29:04Z cfischer $
#
# Kanboard CVE-2014-3920 Cross Site Request Forgery Vulnerability
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
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

CPE = 'cpe:/a:kanboard:kanboard';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111063");
  script_version("$Revision: 14184 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 14:29:04 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-12-04 13:00:00 +0100 (Fri, 04 Dec 2015)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2014-3920");
  script_bugtraq_id(68340);
  script_name("Kanboard CVE-2014-3920 Cross Site Request Forgery Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_kanboard_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("kanboard/installed");

  script_tag(name:"summary", value:"Kanboard is prone to a cross-site request-forgery vulnerability
  because it does not properly validate HTTP requests.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"Exploiting this issue may allow a remote attacker to perform
  certain unauthorized actions. This may lead to further attacks.");
  script_tag(name:"affected", value:"Kanboard versions below 1.0.6 are vulnerable.");
  script_tag(name:"solution", value:"The vendor has released updates listened in the referred advisory.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68340");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/532619/100/0/threaded");
  script_xref(name:"URL", value:"http://kanboard.net/news/version-1.0.6");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"1.0.6" ) ) {

  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     ' + "1.0.6" + '\n';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );