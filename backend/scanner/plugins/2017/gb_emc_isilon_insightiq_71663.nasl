###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_emc_isilon_insightiq_71663.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# EMC Isilon InsightIQ Unspecified Cross Site Scripting Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.140135");
  script_bugtraq_id(71663);
  script_cve_id("CVE-2014-4628");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 12106 $");

  script_name("EMC Isilon InsightIQ Unspecified Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71663");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code  in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory
for more information.");
  script_tag(name:"summary", value:"EMC Isilon InsightIQ is prone to an unspecified cross-site scripting vulnerability because it fails to sanitize user-supplied input.");
  script_tag(name:"affected", value:"Versions prior to EMC Isilon InsightIQ 3.1 are vulnerable.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-31 12:44:39 +0100 (Tue, 31 Jan 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_emc_isilon_insightiq_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("emc/isilon_insightiq/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

if( vers =  get_app_version( cpe:CPE, port:port ) )
{
  if( version_is_less_equal( version: vers, test_version: "3.1" ) )
  {
      security_message( port:port );
      exit (0 );
  }
}

exit( 99 );

