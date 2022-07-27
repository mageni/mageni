###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_wptrackback_dos_vuln.nasl 14012 2019-03-06 09:13:44Z cfischer $
#
# WordPress wp-trackback.php Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.900968");
  script_version("$Revision: 14012 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-06 10:13:44 +0100 (Wed, 06 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-10-29 07:53:15 +0100 (Thu, 29 Oct 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3622");
  script_name("WordPress wp-trackback.php Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37088/");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9431");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53884");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2986");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a Denial of Service
  due to high CPU consumption.");

  script_tag(name:"affected", value:"WordPress version prior to 2.8.5 on all platforms.");

  script_tag(name:"insight", value:"An error occurs in wp-trackbacks.php due to improper validation of user
  supplied data passed into 'mb_convert_encoding()' function. This can be
  exploited by sending multiple-source character encodings into the function.");

  script_tag(name:"solution", value:"Upgrade to WordPress version 2.8.5 or later.");

  script_tag(name:"summary", value:"The host is running WordPress and is prone to Denial of Service
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wpPort = get_app_port(cpe:CPE))
  exit(0);

if(!ver = get_app_version(cpe:CPE, port:wpPort))
  exit(0);

if(version_is_less(version:ver, test_version:"2.8.5")){
  report = report_fixed_ver(installed_version:ver, fixed_version:"2.8.5");
  security_message(port:wpPort, data:report);
  exit(0);
}

exit(99);