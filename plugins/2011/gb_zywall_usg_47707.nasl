###############################################################################
# OpenVAS Vulnerability Test
#
# Multiple ZyWALL USG Products Remote Security Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103161");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2011-05-12 13:24:44 +0200 (Thu, 12 May 2011)");
  script_bugtraq_id(47707);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_name("Multiple ZyWALL USG Products Remote Security Bypass Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/47707");
  script_xref(name:"URL", value:"http://www.redteam-pentesting.de/en/advisories/rt-sa-2011-003/-authentication-bypass-in-configuration-import-and-export-of-zyxel-zywall-usg-appliances");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Reportedly, the issue is fixed. However, Symantec has not confirmed
  this. Please contact the vendor for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Multiple ZyWALL USG products are prone to a security-bypass
  vulnerability.

  Note: Reportedly, the firmware is also prone to a weakness that allows
  password-protected upgrade files to be decrypted with a known plaintext attack.");

  script_tag(name:"impact", value:"Successful exploits may allow attackers to bypass certain security
  restrictions and perform unauthorized actions.");

  script_tag(name:"affected", value:"ZyWALL USG-20 ZyWALL USG-20W ZyWALL USG-50 ZyWALL USG-100 ZyWALL USG-
  200 ZyWALL USG-300 ZyWALL USG-1000 ZyWALL USG-1050 ZyWALL USG-2000");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:443);

url = string("/");

if(http_vuln_check(port:port, url:url, pattern:"<title>ZyWALL USG", usecache:TRUE)) {

  url = string("/cgi-bin/export-cgi/images/?category=config&arg0=startup-config.conf");
  if(http_vuln_check(port:port, url:url, pattern:"model: ZyWALL USG", extra_check:make_list("password","interface","user-type admin"))) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(0);