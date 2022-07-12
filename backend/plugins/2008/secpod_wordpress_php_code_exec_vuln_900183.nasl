###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_php_code_exec_vuln_900183.nasl 14012 2019-03-06 09:13:44Z cfischer $
#
# WordPress 'wp-admin/options.php' Remote Code Execution Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright (c) 2008 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900183");
  script_version("$Revision: 14012 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-06 10:13:44 +0100 (Wed, 06 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-12-26 14:23:17 +0100 (Fri, 26 Dec 2008)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5695");
  script_bugtraq_id(27633);
  script_name("WordPress 'wp-admin/options.php' Remote Code Execution Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/28789");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/5066");
  script_xref(name:"URL", value:"http://mu.wordpress.org/forums/topic.php?id=7534&page&replies=1");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code by
  uploading a PHP script and adding this script pathname to active_plugins.");

  script_tag(name:"affected", value:"WordPress, WordPress prior to 2.3.3
  WordPress, WordPress MU prior to 1.3.2.");

  script_tag(name:"insight", value:"The flaw is due to error under 'wp-admin/options.php' file. These
  can be exploited by using valid user credentials with 'manage_options' and upload_files capabilities.");

  script_tag(name:"solution", value:"Upgrade to version 1.3.2 and 2.3.3 or later.");

  script_tag(name:"summary", value:"The host is running WordPress and is prone to Remote Code
  Execution vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wpPort = get_app_port(cpe:CPE))
  exit(0);

if(!ver = get_app_version(cpe:CPE, port:wpPort))
  exit(0);

if(version_is_less_equal(version:ver, test_version:"2.3.2")){
  report = report_fixed_ver(installed_version:ver, fixed_version:"2.3.2");
  security_message(port:wpPort, data:report);
  exit(0);
}

exit(99);