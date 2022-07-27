###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cloudgate_insecure_direct_object_ref_nd_xss_vuln.nasl 12456 2018-11-21 09:45:52Z cfischer $
#
# Option CloudGate Insecure Direct Object References And XSS Vulnerabilities
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

CPE = "cpe:/o:option:cloudgate";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808246");
  script_version("$Revision: 12456 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:45:52 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-07-04 18:38:14 +0530 (Mon, 04 Jul 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Option CloudGate Insecure Direct Object References And XSS Vulnerabilities");

  script_tag(name:"summary", value:"The host is running Option CloudGate
  and is prone to cross site scripting and insecure direct object reference
  authorization bypass vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to bypass authorization and access resource or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The application provides direct access to objects based on user-supplied input.

  - An insufficient validation of user supplied input by API's.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script into user's browser session and also
  to bypass authorization and access resources and functionalities in the system
  directly, for example APIs, files, upload utilities, device settings, etc.");

  script_tag(name:"affected", value:"Option CloudGate CG0192-11897");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.option.com");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40016");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_option_cloudgate_remote_detect.nasl");
  script_mandatory_keys("Option/CloudGate/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!cloudPort = get_app_port(cpe:CPE)){
  exit(0);
}

url = "/partials/firewall.html";

sndReq = http_get(item:url, port:cloudPort);
rcvRes = http_send_recv(port:cloudPort, data:sndReq);

if(http_vuln_check(port:cloudPort, url:url, check_header:TRUE,
                   pattern:"navigation.firewall' | i18n",
                   extra_check:make_list("firewall.defaultPolicies", "firewall.rebootChanges",
                                         "firewall.staticRouting.editStaticRouting")))

{
  report = report_vuln_url(port:cloudPort, url:url);
  security_message(port:cloudPort, data:report);
  exit(0);
}
