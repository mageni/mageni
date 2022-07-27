###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pivot_xss_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Pivot <= 1.40.7 Cross Site Scripting Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:pivot:pivot";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900579");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-2133", "CVE-2009-2134");
  script_bugtraq_id(35363);
  script_name("Pivot Cross Site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_pivot_detect.nasl");
  script_mandatory_keys("Pivot/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35363");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8941");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass
  security restrictions by gaining sensitive information, exectue arbitrary
  html or webscript code and redirect the user to other malicious sites.");

  script_tag(name:"affected", value:"Pivot version 1.40.7 and prior.");

  script_tag(name:"insight", value:"- The input passed into several parameters in the pivot/index.php and
  pivot/user.php is not sanitised before being processed.

  - An error in pivot/tb.php while processing invalid url parameter reveals
  sensitive information such as the installation path in an error message.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is installed with Pivot and is prone to a Cross Site
  Scripting vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit(0);

if( version_is_less_equal( version:vers, test_version:"1.40.7" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );