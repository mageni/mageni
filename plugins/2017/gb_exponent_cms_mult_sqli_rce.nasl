###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_exponent_cms_mult_sqli_rce.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Exponent CMS < 2.4.0 Multiple SQL Injection and Remote Code Execution Vulnerabilities
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:exponentcms:exponent_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108093");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2016-7400", "CVE-2016-7565", "CVE-2016-7780", "CVE-2016-7781",
                "CVE-2016-7782", "CVE-2016-7783", "CVE-2016-7784", "CVE-2016-7788",
                "CVE-2016-7789", "CVE-2016-7790", "CVE-2016-7791", "CVE-2016-9019",
                "CVE-2016-9020", "CVE-2016-9087");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-09 12:45:17 +0100 (Thu, 09 Mar 2017)");
  script_name("Exponent CMS < 2.4.0 Multiple SQL Injection and Remote Code Execution Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_exponet_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ExponentCMS/installed");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Nov/12");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/139484/Exponent-CMS-2.3.9-SQL-Injection.html");
  script_xref(name:"URL", value:"http://www.exponentcms.org/news/version-2-4-0-released");

  script_tag(name:"summary", value:"This host is installed with Exponent CMS
  and is prone to multiple sql injection and remote code execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to e.g dump database data out to a malicious server or execute code
  via the /install/index.php setup tool.");

  script_tag(name:"affected", value:"Exponent CMS 2.3.9 and earlier.");

  script_tag(name:"solution", value:"Upgrade to version 2.4.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"2.4.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.4.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );