###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_modx_brute_force_n_path_disc_vuln.nasl 12175 2018-10-31 06:20:00Z ckuersteiner $
#
# MODX Brute Force and Path Disclosure Vulnerabilities
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802495");
  script_version("$Revision: 12175 $");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-31 07:20:00 +0100 (Wed, 31 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-11-21 10:48:20 +0530 (Wed, 21 Nov 2012)");
  script_name("MODX Brute Force and Path Disclosure Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_modx_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("modx_cms/installed");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Nov/142");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/118240/modx-brutedisclose.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow the attacker to obtain
  sensitive information that could aid in further attacks.");

  script_tag(name:"affected", value:"MODX CMF version 2.x (Revolution)
  MODX CMS version 1.x (Evolution)");

  script_tag(name:"insight", value:"- In login form (manager/index.php) there is no reliable
  protection from brute force attacks.

  - Insufficient error checking, allows remote attackers to obtain sensitive
  information via a direct request to a .php file, which reveals the
  installation path in an error message.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is installed with MODX and is prone to brute force and
  path disclosure vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

cpe_list = make_list( "cpe:/a:modx:unknown",
                      "cpe:/a:modx:revolution",
                      "cpe:/a:modx:evolution" );

if( ! infos = get_all_app_ports_from_list( cpe_list:cpe_list ) ) exit( 0 );
cpe = infos['cpe'];
port = infos['port'];

if( ! dir = get_app_location( cpe:cpe, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";
url = dir + '/manager/includes/browsercheck.inc.php';

# Don't use check_headers. A 500 error is thrown here on this request
if( http_vuln_check( port:port, url:url, pattern:"Failed opening required 'MODX_BASE_PAT.*browsercheck.inc.php",
                     extra_check:make_list( 'phpSniff.class.php','MODX_BASE_PATH' ) ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
