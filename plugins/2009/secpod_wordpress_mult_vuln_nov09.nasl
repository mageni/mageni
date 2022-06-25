###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_mult_vuln_nov09.nasl 14012 2019-03-06 09:13:44Z cfischer $
#
# WordPress Multiple Vulnerabilities - Nov09
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900975");
  script_version("$Revision: 14012 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-06 10:13:44 +0100 (Wed, 06 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-11-20 06:52:52 +0100 (Fri, 20 Nov 2009)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3890", "CVE-2009-3891");
  script_bugtraq_id(37014, 37005);
  script_name("WordPress Multiple Vulnerabilities - Nov09");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37332");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/11/15/2");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary PHP code by uploading
  malicious PHP files and to inject arbitrary web script or HTML code which
  will be executed in a user's browser session.");

  script_tag(name:"affected", value:"WordPress version prior to 2.8.6.");

  script_tag(name:"insight", value:"- The 'wp_check_filetype()' function in /wp-includes/functions.php does not
  properly validate files before uploading them.

  - Input passed into the 's' parameter in press-this.php is not sanitised
  before being displayed to the user.");

  script_tag(name:"solution", value:"Update to Version 2.8.6 or later.");

  script_tag(name:"summary", value:"The host is running WordPress and is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wpPort = get_app_port(cpe:CPE))
  exit(0);

if(!wpVer = get_app_version(cpe:CPE, port:wpPort))
  exit(0);

if(version_is_less(version:wpVer, test_version:"2.8.6")){
  report = report_fixed_ver(installed_version:wpVer, fixed_version:"2.8.6");
  security_message(port:wpPort, data:report);
  exit(0);
}

exit(99);