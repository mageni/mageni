###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_config_info_disc_vuln.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# phpMyAdmin 'show_config_errors.php' Information Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802430");
  script_version("$Revision: 14117 $");
  script_bugtraq_id(52858);
  script_cve_id("CVE-2012-1902");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-04-17 12:56:58 +0530 (Tue, 17 Apr 2012)");
  script_name("phpMyAdmin 'show_config_errors.php' Information Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://english.securitylab.ru/nvd/422861.php");
  script_xref(name:"URL", value:"http://www.auscert.org.au/render.html?it=15653");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=809146");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2012-2.php");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_active");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpMyAdmin/installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive
  information that could aid in further attacks.");
  script_tag(name:"affected", value:"phpMyAdmin Version 3.4.10.2 and prior");
  script_tag(name:"insight", value:"The flaw is due to an input validation error in
  'show_config_errors.php'. When a configuration file does not exist, allows
  remote attackers to obtain sensitive information via a direct request.");
  script_tag(name:"solution", value:"Upgrade to phpMyAdmin 3.4.10.2 later.");

  script_tag(name:"summary", value:"This host is running phpMyAdmin and is prone to information
  disclosure vulnerability.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/downloads.php");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);

if(dir = get_app_location(cpe:CPE, port:port))
{
  url = dir + "/show_config_errors.php";

  if(http_vuln_check(port:port, url:url, check_header: TRUE,
     pattern:"Failed opening required.*\show_config_errors.php")) {
    security_message(port:port);
  }
}

exit(0);
