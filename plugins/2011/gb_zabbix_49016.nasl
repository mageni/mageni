###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zabbix_49016.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# ZABBIX 'backurl' Parameter Cross Site Scripting Vulnerability
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
CPE = "cpe:/a:zabbix:zabbix";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103213");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-19 14:58:19 +0200 (Fri, 19 Aug 2011)");
  script_bugtraq_id(49016);
  script_cve_id("CVE-2011-2904");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("ZABBIX 'backurl' Parameter Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49016");
  script_xref(name:"URL", value:"http://www.zabbix.com/rn1.8.6.php");
  script_xref(name:"URL", value:"http://www.zabbix.org");
  script_xref(name:"URL", value:"https://support.zabbix.com/browse/ZBX-3835");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("zabbix_detect.nasl", "zabbix_web_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Zabbix/installed");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"ZABBIX is prone to a cross-site scripting vulnerability because it
fails to properly sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks.

Version prior to ZABBIX 1.8.6 are vulnerable.");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");

include("version_func.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(vers = get_app_version(cpe:CPE, port:port)) {

  if(version_is_less(version: vers, test_version: "1.8.6")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
