# OpenVAS Vulnerability Test
# $Id: php_fusion_6_00_206_sql_injection.nasl 14240 2019-03-17 15:50:45Z cfischer $
# Description: PHP-Fusion <= 6.00.206 Forum SQL Injection Vulnerability
#
# Authors:
# Ferdy Riphagen <f[dot]riphagen[at]nsec[dot]nl>
# Updated: 04/07/2009 Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2005 Ferdy Riphagen
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.200010");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2005-3740");
  script_bugtraq_id(15502);
  script_name("PHP-Fusion <= 6.00.206 Forum SQL Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2005 Ferdy Riphagen");
  script_dependencies("secpod_php_fusion_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("php-fusion/installed");

  script_tag(name:"solution", value:"Apply the patch from the php-fusion main site.");

  script_tag(name:"summary", value:"A vulnerability is reported in the forum module of PHP-Fusion
  6.00.206 and some early released versions.");

  script_tag(name:"impact", value:"When the forum module is activated, a registered user can execute
  arbitrary SQL injection commands.");

  script_tag(name:"insight", value:"The failure exists because the application does not properly sanitize
  user-supplied input in 'options.php' and 'viewforum.php' before using it in the SQL query, and
  magic_quotes_gpc is set to off.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15502");
  script_xref(name:"URL", value:"http://secunia.com/advisories/17664/");
  script_xref(name:"URL", value:"http://www.php-fusion.co.uk/downloads.php?cat_id=3");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
version = get_kb_item("www/" + port + "/php-fusion");
if(!version)
  exit(0);

if(version_is_less_equal(version:version, test_version:"6.00.206")){
  security_message(port);
}