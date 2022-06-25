###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_mult_vuln03_feb16.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# phpMyAdmin Multiple Vulnerabilities -03 Feb16
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807079");
  script_version("$Revision: 12051 $");
  script_cve_id("CVE-2016-2042", "CVE-2016-2043");
  script_bugtraq_id(82097, 82101);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-02-23 10:17:05 +0530 (Tue, 23 Feb 2016)");
  script_tag(name:"qod_type", value:"remote_active");
  script_name("phpMyAdmin Multiple Vulnerabilities -03 Feb16");

  script_tag(name:"summary", value:"This host is installed with phpMyAdmin
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to obtain sensitive information or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - recommended setting of the PHP configuration directive display_errors is
    set to on, which is against the recommendations given in the PHP manual
    for a production server.

  - Insufficient validation of user supplied input via a table name to the
    normalization page in the 'goToFinish1NF' function in
    'js/normalization.js' script");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information about the server and to inject
  arbitrary web script or HTML.");

  script_tag(name:"affected", value:"phpMyAdmin versions 4.4.x prior to 4.4.15.3
  and 4.5.x prior to 4.5.4");

  script_tag(name:"solution", value:"Upgrade to phpMyAdmin version 4.4.15.3 or
  4.5.4 or or later or apply patch from the link mentioned in reference.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-6");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-7");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
  script_mandatory_keys("phpMyAdmin/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = dir + '/libraries/phpseclib/Crypt/AES.ph';

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:"Fatal error.*Crypt/AES.php"))
{
  report = report_vuln_url( port:http_port, url:url );
  security_message(port:http_port, data:report);
  exit(0);
}
