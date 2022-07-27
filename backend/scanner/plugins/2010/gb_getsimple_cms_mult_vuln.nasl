##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_getsimple_cms_mult_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# GetSimple CMS Multiple Vulnerabilities.
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:getsimple:getsimple";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801410");
  script_version("$Revision: 13960 $");
  script_cve_id("CVE-2010-5052", "CVE-2010-4863");
  script_bugtraq_id(41697);
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("GetSimple CMS Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_getsimple_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("GetSimple_cms/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/40428");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2010/May/234");

  script_tag(name:"insight", value:"The flaws are due to, input passed to various scripts via various
  parameters are not properly sanitized before being returned to the user.");

  script_tag(name:"solution", value:"Upgrade to version 2.03 or later.");

  script_tag(name:"summary", value:"This host is running GetSimple CMS and is prone to multiple
  vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.");
  script_tag(name:"affected", value:"GetSimple CMS version 2.01");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://get-simple.info/download");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_equal( version:vers, test_version:"2.01" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.03" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );