###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_emc_isilon_insightiq_95945.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# EMC Isilon InsightIQ Authentication Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:emc:isilon_insightiq";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140146");
  script_bugtraq_id(95945);
  script_cve_id("CVE-2017-2765");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 12106 $");

  script_name("EMC Isilon InsightIQ Authentication Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95945");
  script_xref(name:"URL", value:"http://www.emc.com/");

  script_tag(name:"impact", value:"An attacker can exploit this issue to bypass authentication mechanism and perform unauthorized actions. This may lead to further attacks.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory for more information.");
  script_tag(name:"summary", value:"EMC Isilon InsightIQ is prone to an authentication-bypass vulnerability.");
  script_tag(name:"affected", value:"EMC Isilon InsightIQ versions 4.1.0, 4.0.1, 4.0.0, 3.2.2, 3.2.1, 3.2.0, 3.1.1, 3.1.0, 3.0.1 and 3.0.0 are vulnerable.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-02 11:06:53 +0100 (Thu, 02 Feb 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_emc_isilon_insightiq_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("emc/isilon_insightiq/version");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

if( vers = get_app_version( cpe:CPE, port:port ) )
{
  if( version_is_less( version: vers, test_version: "4.1.1" ) )
  {
      report = report_fixed_ver( installed_version:vers, fixed_version:"4.1.1");
      security_message( port:port, data:report );
      exit(0 );
  }
}

exit( 99 );
